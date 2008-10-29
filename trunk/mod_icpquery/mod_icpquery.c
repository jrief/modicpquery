// 
// Name: mod_icpquery - an Apache module to extend the RewriteMap configuration 
// directive as offered by mod_rewrite by additional internal mappig functions:
// Search for a cached web object using ICP as defined by RFC-2186.
// Author: Jacob Rief
// License: Apache Public License

#include "defaults.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"

#include <apr_lib.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_file_info.h>
#include <apr_network_io.h>

#if defined AP_NEED_SET_MUTEX_PERMS
# include "unixd.h"
#endif
#ifndef MOD_REWRITE_H
# include "apr_optional.h"

// rewrite map function prototype
typedef char *(rewrite_mapfunc_t)(request_rec *r, char *key);

// optional function declaration
APR_DECLARE_OPTIONAL_FN(void, ap_register_rewrite_mapfunc, (char *name, rewrite_mapfunc_t *func));
#endif

module AP_MODULE_DECLARE_DATA APMODULE;

typedef struct icpquery_config {
	// search for cached objects on remote servers using ICP-queries
	int icpquery_enabled;
	apr_socket_t* icp_socket;
	apr_sockaddr_t* icp_bindaddr;
	apr_array_header_t* icp_peer_addrs;
	apr_array_header_t* icp_mcast_addrs;
	apr_interval_time_t icp_timeout;
	apr_byte_t icp_mcasthops;
	// logfile handling 
	char* logfile;
	int loglevel;
	apr_file_t *logfp;
	// the corresponding server indicator
	server_rec *server;  
} icpquery_config;

// opcodes and icp_message as defined in http://icp.ircache.net/rfc2186.txt
typedef enum icp_opcode {
	ICP_OP_INVALID = 0,
	ICP_OP_QUERY = 1,
	ICP_OP_HIT = 2,
	ICP_OP_MISS = 3,
	ICP_OP_ERR = 4,
	ICP_OP_SECHO = 10,
	ICP_OP_DECHO = 11,
	ICP_OP_MISS_NOFETCH = 21,
	ICP_OP_DENIED = 22,
	ICP_OP_HIT_OBJ = 23,
} icp_opcode;

typedef struct icp_message_t {
	unsigned char opcode;
	unsigned char version;
	unsigned short int length;
	unsigned int request;
	unsigned int options;
	unsigned int data;
	unsigned int sender;
	char payload[1024];
} icp_message_t;

// mutex to exclude concurrent wrinting into the logfile
static
apr_global_mutex_t *icpquery_log_mutex = NULL;

// Debug logging for mod_icpquery.
// Fatal errors are reported using ap_log_error.
// Consider these logleves as useful:
// 0: Log all kind of problems.
// 1: Log the final result as delivered to the corresponding RewriteMap
// 2: Log informative messages
// 3: Debug logging
static
void do_log(icpquery_config *sconf, int level, apr_status_t statcode, const char *text, ...)
{
	char str1[128];
	char str2[512];
	char str4[256];
	char str3[1024];
	va_list ap;
	apr_status_t rv;
	apr_time_exp_t timenow;
	apr_size_t tlen;

	if (!sconf->logfp || !sconf->logfile || sconf->logfile[0]=='\0' || level>sconf->loglevel)
		return;
	apr_time_exp_lt(&timenow, apr_time_now());
	apr_strftime(str1, &tlen, sizeof(str1), "%d/%b/%Y:%H:%M:%S", &timenow);
	if (statcode!=APR_SUCCESS)
		apr_strerror(statcode, str3, sizeof(str3));
	else
		str3[0] = '\0';
	va_start(ap, text);
	apr_vsnprintf(str2, sizeof(str2), text, ap);
	apr_snprintf(str4, sizeof(str4), "[%s] (%d) %s. %s" APR_EOL_STR, str1, level, str2, str3);

	rv = apr_global_mutex_lock(icpquery_log_mutex);
	if (rv!=APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, 0, "apr_global_mutex_lock(icpquery_log_mutex) failed");
		goto leave;
	}
	tlen = strlen(str4);
	apr_file_write(sconf->logfp, str4, &tlen);
	rv = apr_global_mutex_unlock(icpquery_log_mutex);
	if (rv!=APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, 0, "apr_global_mutex_unlock(icpquery_log_mutex) failed");
		goto leave;
	}
    leave:
	va_end(ap);
	return;
}

static
char* pstrdup_opcode(int opcode, apr_pool_t* pool)
{
	switch (opcode) {
	    case ICP_OP_INVALID:
		return apr_pstrdup(pool, "ICP_INVALID");
	    case ICP_OP_QUERY:
		return apr_pstrdup(pool, "ICP_QUERY");
	    case ICP_OP_HIT:
		return apr_pstrdup(pool, "ICP_HIT");
	    case ICP_OP_MISS:
		return apr_pstrdup(pool, "ICP_MISS");
	    case ICP_OP_ERR:
		return apr_pstrdup(pool, "ICP_ERR");
	    case ICP_OP_SECHO:
		return apr_pstrdup(pool, "ICP_SECHO");
	    case ICP_OP_DECHO:
		return apr_pstrdup(pool, "ICP_DECHO");
	    case ICP_OP_MISS_NOFETCH:
		return apr_pstrdup(pool, "ICP_MISS_NOFETCH");
	    case ICP_OP_DENIED:
		return apr_pstrdup(pool, "ICP_DENIED");
	    case ICP_OP_HIT_OBJ:
		return apr_pstrdup(pool, "ICP_HIT_OBJ");
	    default:
		break;
	}
	return apr_pstrdup(pool, "ICP_OP_UNKNOWN");
}

static
int init_icpquery_socket(apr_pool_t *pool, server_rec *s)
{
	apr_status_t rv;
	icpquery_config *sconf = ap_get_module_config(s->module_config, &APMODULE);
	if (!sconf->icpquery_enabled)
		return 1;

	// create the socket 
	if ((rv = apr_socket_create(&sconf->icp_socket, APR_INET, SOCK_DGRAM, APR_PROTO_UDP, pool))!=APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, "mod_icpquery: failed to create ICP socket");
		return 0;
	}
	// join the multicast group(s)
	int i;
	apr_sockaddr_t** mcastgroup = (apr_sockaddr_t**)sconf->icp_mcast_addrs->elts;
	for (i = 0; i<sconf->icp_mcast_addrs->nelts; ++i) {
		apr_sockaddr_t* mcg = mcastgroup[i];
		char* maddr;
		apr_sockaddr_ip_get(&maddr, mcg);
		do_log(sconf, 2, 0, "Join multicast group '%s'", maddr);
		if ((rv = apr_mcast_loopback(sconf->icp_socket, 0))!=APR_SUCCESS
		 || (rv = apr_mcast_hops(sconf->icp_socket, sconf->icp_mcasthops))!=APR_SUCCESS
		 || (rv = apr_mcast_join(sconf->icp_socket, mcg, sconf->icp_bindaddr, NULL))!=APR_SUCCESS
		 || (rv = apr_mcast_interface(sconf->icp_socket, sconf->icp_bindaddr))!=APR_SUCCESS
		 || (rv = apr_socket_opt_set(sconf->icp_socket, APR_SO_REUSEADDR, 1))!=APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, "mod_icpquery: socket failed to join mcast group");
			return 0;
		}
	}
	do_log(sconf, 1, 0, "Created socket for ICP communication");
	return 1;
}

static
int send_icp_datagrams(request_rec *req, char* key, apr_uint32_t request_no)
{
	apr_status_t rv;
	char *toaddr;
	char buffer[MAXBUFLEN];

	icpquery_config *sconf = ap_get_module_config(req->server->module_config, &APMODULE);
	// setup icp message to send as UDP datagram
	apr_size_t length = strlen(key)+1;
	if (length>MAXBUFLEN-32) length = MAXBUFLEN-32;
	icp_message_t* icp = (icp_message_t*)buffer;
	icp->opcode = ICP_OP_QUERY;
	icp->version = 2;
	icp->request = icp->options = icp->data = 0;
	apr_cpystrn(&icp->payload[4], key, length);
	icp->request = htonl(request_no);
	length += 24;
	icp->length = htons(length);
	// send the datagram to the list of unicast addresses
	apr_sockaddr_t** peers = (apr_sockaddr_t**)sconf->icp_peer_addrs->elts;
	int i;
	for (i = 0; i<sconf->icp_peer_addrs->nelts; ++i) {
		apr_sockaddr_t* p = peers[i];
		apr_sockaddr_ip_get(&toaddr, p);
		do_log(sconf, 3, 0, "Sending ICP query='%s' to %s:%d [req=%u] as unicast", key, toaddr, p->port, request_no);
		if ((rv = apr_socket_sendto(sconf->icp_socket, p, 0, buffer, &length))!=APR_SUCCESS)
			do_log(sconf, 0, rv, "Error while sending ICP datagram: %d");
	}
	// use a different request_no to distinguish unicast from multicast addresses
	request_no++;
	icp->request = htonl(request_no);
	// send the datagram to the list of multicast address
	peers = (apr_sockaddr_t**)sconf->icp_mcast_addrs->elts;
	for (i = 0; i<sconf->icp_mcast_addrs->nelts; ++i) {
		apr_sockaddr_t* p = peers[i];
		apr_sockaddr_ip_get(&toaddr, p);
		do_log(sconf, 3, 0, "Sending ICP query='%s' to %s:%d [req=%u] as multicast", key, toaddr, p->port, request_no);
		if ((rv = apr_socket_sendto(sconf->icp_socket, p, 0, buffer, &length))!=APR_SUCCESS)
			do_log(sconf, 0, rv, "Error while sending ICP datagram: %d");
	}
	return 1;
}

static
int receive_icp_datagrams(request_rec *req, apr_uint32_t unicast_request_no, char* value)
{
	apr_status_t rv;
	apr_int32_t nsds;
	apr_int32_t multicast_request_no = unicast_request_no+1;
	int writelen = 0;
	int num_hits = 0;
	char key[20];
	char buffer[MAXBUFLEN];
	apr_size_t bufsize = MAXBUFLEN-1;
	apr_sockaddr_t* recfrom;
	char* fromaddr;

	// initialize lookup table to remember which caches have sent a valid ICP-reply 
	apr_table_t *running_caches = apr_table_make(req->pool, 0);
	apr_snprintf(key, sizeof(key), "%x", (unsigned int)running_caches);

	// remember table running_caches, dump address as hex-string into req->notes
	apr_table_set(req->notes, "Running-Caches", key);

	icpquery_config* sconf = ap_get_module_config(req->server->module_config, &APMODULE);
	if ((rv = apr_sockaddr_info_get(&recfrom, APR_ANYADDR, APR_INET, 0, 0, req->pool))!=APR_SUCCESS) {
		do_log(sconf, 0, rv, "Error while setting recfrom");
		return 0;
	}
	// create descriptor to enter poll loop
	icp_message_t* icp = (icp_message_t*)buffer;
        apr_pollfd_t pollfd = { req->pool, APR_POLL_SOCKET, APR_POLLIN, 0, { NULL }, NULL };
        pollfd.desc.s = sconf->icp_socket;
	apr_int32_t unicast_nelts = sconf->icp_peer_addrs->nelts;
 	apr_interval_time_t timeout = sconf->icp_timeout;
	apr_time_t starttime = apr_time_now();
	while (timeout>0) {
		// wait for UDP datagram to arrive
		do_log(sconf, 3, 0, "Listening for datagrams for max %u microseconds", timeout);
		if ((rv = apr_poll(&pollfd, 1, &nsds, timeout))==APR_TIMEUP)
			break;
		if (rv!=APR_SUCCESS) {
			do_log(sconf, 0, rv, "Error while polling icp_socket");
			return 0;
		}
		if ((rv = apr_socket_recvfrom(recfrom, sconf->icp_socket, 0, buffer, &bufsize))!=APR_SUCCESS) {
			do_log(sconf, 0, rv, "Error while receiving ICP datagram");
			return 0;
		}
		// read ICP datagram and compare it to sent data
		icp->version = ntohl(icp->version);
		icp->request = ntohl(icp->request);
		apr_sockaddr_ip_get(&fromaddr, recfrom);
		do_log(sconf, 3, 0, "Recieved UDP datagram with %d bytes from %s:%d [req=%u]",
		     bufsize, fromaddr, recfrom->port, icp->request);
		timeout -= apr_time_now()-starttime;
		if (bufsize==0)
			continue;
		if (icp->request!=unicast_request_no && icp->request!=multicast_request_no)
			continue;
		do_log(sconf, 2, 0, "Valid ICP-reply contains %s from %s", pstrdup_opcode(icp->opcode, req->pool), fromaddr);
		if (icp->opcode==ICP_OP_HIT) {
			num_hits++;
			writelen += apr_snprintf(value+writelen, LONG_STRING_LEN-writelen, "%s;", fromaddr);
		}
		// also remember caches sending ICP_MISS, so that cacheisrunning can tell
		// the client about working caches.
		apr_snprintf(key, 20, "%s", fromaddr);
		apr_table_set(running_caches, key, "ok");
		do_log(sconf, 3, 0, "Mark cache[%s] as running", key);
		if (icp->request==unicast_request_no) {
			// in case the query was done exclusively with ICP-unicast 
			// and each cache answered the query, then leave the loop immediately.
			unicast_nelts--;
			if (unicast_nelts==0 && sconf->icp_mcast_addrs->nelts==0) {
				do_log(sconf, 3, 0, "No more ICP-replies expected for this query: premature timeout");
				break;
			}
		}
	}
	return num_hits;
}

// Query all of the configured peer caches with `key` using ICP as UDP multicast and/or unicast.
// This function returns a semicolon seperated list of all caches which hold the object with
// the requested key.
static
char *icp_query_map(request_rec *req, char *key)
{
	icpquery_config *sconf = ap_get_module_config(req->server->module_config, &APMODULE);
	if (!sconf->icpquery_enabled || key==NULL)
		return NULL;
	// create a random request number to compare against ICP replies
	apr_uint32_t request_no;
	apr_generate_random_bytes((unsigned char*)&request_no, sizeof(request_no));	

	// send the query
	send_icp_datagrams(req, key, request_no);

	// collect ICP-replies into the string 'value'
	char* value = apr_pcalloc(req->pool, LONG_STRING_LEN);
	if (receive_icp_datagrams(req, request_no, value)>0) {
		do_log(sconf, 1, 0, "ICP-query map ok: key=%s -> val=%s", key, value);
		return value;
	}
	do_log(sconf, 1, 0, "ICP-query map failed: no cache found for key=%s", key);
	return NULL;
}

// Inform the caller, if the cache host specified as key recently has anserwed a query
// request or not. Call this function ONLY after having called 'icp_query_map' using
// the named RewriteMap. The reason for this is, that 'icp_query_map' remembers
// the information about all caches, whether they replied with ICP_HIT or ICP_MISS.
// Thus, use this function to check whether a cache is running or not.
static
char* icp_check_cache(request_rec *req, char *key)
{
	icpquery_config* sconf = ap_get_module_config(req->server->module_config, &APMODULE);
	if (key==NULL) {
		do_log(sconf, 0, 0, "Can't map null keys");
		return NULL;
	}
	const char* rc = apr_table_get(req->notes, "Running-Caches");
	if (rc==NULL) {
		do_log(sconf, 0, 0, "req->notes does not contain any valid table information", key);
		return NULL;
	}
	// extract the location for the table of running caches using the req->notes field
	apr_table_t* running_caches = (apr_table_t*)apr_strtoi64(rc, NULL, 16);
	if (apr_table_get(running_caches, key)) {
		do_log(sconf, 1, 0, "Checked cache '%s' up and running", key);
		return key;
	} else {
		do_log(sconf, 1, 0, "Checked cache '%s' not available", key);
		return NULL;
	}
}

static
void *create_server_config(apr_pool_t *pool, server_rec *s)
{
	icpquery_config *sconf = (icpquery_config*) apr_pcalloc(pool, sizeof(icpquery_config));
	sconf->server = s;
	sconf->logfile = NULL;
	sconf->loglevel = 0;
	sconf->logfp = NULL;
	sconf->icpquery_enabled = 0;
	sconf->icp_peer_addrs = apr_array_make(pool, 0, sizeof(apr_sockaddr_t*));
	sconf->icp_mcast_addrs = apr_array_make(pool, 0, sizeof(apr_sockaddr_t*));
	apr_status_t rv;
	char hostname[APRMAXHOSTLEN+1];
	if ((rv = apr_gethostname(hostname, APRMAXHOSTLEN, pool))!=APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, "mod_icpquery: Failed to find local hostname");
		return NULL;
	}
	if ((rv = apr_sockaddr_info_get(&sconf->icp_bindaddr, hostname, APR_INET, 0, 0, pool))!=APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, "mod_icpquery: Failed to find IP address for '%s'", hostname);
		return NULL;
	}
	sconf->icp_mcasthops = 3;
	sconf->icp_timeout = 100000;
	 
	return (void*) sconf;
}

static
void *merge_server_config(apr_pool_t *pool, void *basecfg, void *virtualcfg)
{
	icpquery_config *merge_conf = (icpquery_config*) apr_pcalloc(pool, sizeof(icpquery_config));
	icpquery_config *base_conf = (icpquery_config*) basecfg;
	icpquery_config *virtual_conf = (icpquery_config*) virtualcfg;

	merge_conf->loglevel = virtual_conf->loglevel ? virtual_conf->loglevel : base_conf->loglevel;
	merge_conf->logfile = NULL;
	merge_conf->logfp = NULL;
	if (virtual_conf->icpquery_enabled) {
		merge_conf->icpquery_enabled = virtual_conf->icpquery_enabled;
		merge_conf->icp_peer_addrs = apr_array_append(pool, base_conf->icp_peer_addrs, virtual_conf->icp_peer_addrs);
		merge_conf->icp_mcast_addrs = apr_array_append(pool, base_conf->icp_mcast_addrs, virtual_conf->icp_mcast_addrs);
		merge_conf->icp_mcasthops = virtual_conf->icp_mcasthops;
		merge_conf->icp_bindaddr = virtual_conf->icp_bindaddr;
		merge_conf->icp_timeout = virtual_conf->icp_timeout;
	} else if (base_conf->icpquery_enabled) {
		merge_conf->icpquery_enabled = base_conf->icpquery_enabled;
		merge_conf->icp_peer_addrs = apr_array_copy(pool, base_conf->icp_peer_addrs);
		merge_conf->icp_mcast_addrs = apr_array_copy(pool, base_conf->icp_mcast_addrs);
		merge_conf->icp_mcasthops = base_conf->icp_mcasthops;
		merge_conf->icp_bindaddr = base_conf->icp_bindaddr;
		merge_conf->icp_timeout = base_conf->icp_timeout;
	} else {
		merge_conf->icpquery_enabled = 0;
	}
	merge_conf->server = virtual_conf->server;
	return merge_conf;
}

static
int open_logfile(server_rec *s, apr_pool_t *pool)
{
	apr_status_t rv;
	icpquery_config *sconf = ap_get_module_config(s->module_config, &APMODULE);
	if (sconf->logfile==NULL || sconf->logfile[0]=='\0' || sconf->logfp) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, APR_EBADPATH, s,
		    "mod_icpquery: Not specifying a private logfile makes error tracking very hard");
		return 1;
	}
	const char* filename = ap_server_root_relative(pool, sconf->logfile);
	if (!filename) {
		ap_log_error(APLOG_MARK, APLOG_ERR, APR_EBADPATH, s,
		     "mod_icpquery: Invalid ICPQueryLogfile %s", sconf->logfile);
		return 0;
	}
	int log_flags = APR_WRITE | APR_APPEND | APR_CREATE;
	apr_fileperms_t log_mode = APR_UREAD | APR_UWRITE | APR_GREAD | APR_WREAD;
	if ((rv = apr_file_open(&sconf->logfp, filename, log_flags, log_mode, pool)) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, "mod_icpquery: could not open logfile %s", filename);
		return 0;
	}
	return 1;
}

static
int pre_config(apr_pool_t *pool, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	APR_OPTIONAL_FN_TYPE(ap_register_rewrite_mapfunc) *map_pfn_register;
	map_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_rewrite_mapfunc);
	if (map_pfn_register==NULL) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "mod_icpquery: could not initialize module");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	map_pfn_register(ICPQUERYMAPPER, icp_query_map);
	map_pfn_register(CHECKCACHEMAPPER, icp_check_cache);
	return OK;
}

static
int post_config(apr_pool_t *pool, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	apr_status_t rv;
	if ((rv = apr_global_mutex_create(&icpquery_log_mutex, NULL, APR_LOCK_DEFAULT, pool)) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "mod_icpquery: could not create mutex-lock for ICPQueryLog");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
#ifdef AP_NEED_SET_MUTEX_PERMS
	rv = unixd_set_global_mutex_perms(icpquery_log_mutex);
	if (rv != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
		    "mod_icpquery: Could not set permissions on ICPQueryLog; check User and Group directives");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
#endif

	// for each server, do the post_config
	icpquery_config *sconf = ap_get_module_config(s->module_config, &APMODULE);
	if (sconf==NULL) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "mod_icpquery: could not initialize module");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	server_rec *si;
	if (open_logfile(s, pool)) {
		for (si = s; si; si = si->next) {
			icpquery_config *sicfg = ap_get_module_config(si->module_config, &APMODULE);
			sicfg->logfile = sconf->logfile;
			sicfg->logfp = sconf->logfp;
		}
	} else {
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	for (si = s; si; si = si->next) {
		if (!init_icpquery_socket(pool, si))
			return HTTP_INTERNAL_SERVER_ERROR;
	}
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "Initialized mod_icpquery (version="VERSION")");
	return OK;
}

static
void init_child(apr_pool_t *p, server_rec *s)
{
	apr_status_t rv;
	if ((rv = apr_global_mutex_child_init(&icpquery_log_mutex, NULL, p))!=APR_SUCCESS)
		ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "mod_icpquery: could not init log-lock in child");
}

static
const char *cmd_mapping_engine(cmd_parms *cmd, void *dconf, int onoff)
{
	const char *error;
	if ((error = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT)) != NULL)
		return error;
	icpquery_config *sconf = ap_get_module_config(cmd->server->module_config, &APMODULE);
	if (sconf==NULL)
		return "mod_icpquery not yet loaded";
	sconf->icpquery_enabled = onoff;
	return NULL;
}

static
const char *cmd_logfile(cmd_parms *cmd, void *dconf, const char *filename)
{
	const char *error;
	if ((error = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT)) != NULL)
		return error;
	icpquery_config *sconf = ap_get_module_config(cmd->server->module_config, &APMODULE);
	if (sconf==NULL)
		return "mod_icpquery not yet loaded";
	sconf->logfile = apr_pstrdup(cmd->pool, filename);
	return NULL;
}

static
const char *cmd_loglevel(cmd_parms *cmd, void *dconf, const char *loglevel)
{
	const char *error;
	if ((error = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT)) != NULL)
		return error;
	icpquery_config *sconf = ap_get_module_config(cmd->server->module_config, &APMODULE);
	if (sconf==NULL)
		return "mod_icpquery not yet loaded";
	sconf->loglevel = atoi(loglevel);
	return NULL;
}

static
const char *cmd_peeraddr(cmd_parms *cmd, void *dconf, const char *peeraddr)
{
	const char *error;
	if ((error = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT)) != NULL)
		return error;
	icpquery_config *sconf = ap_get_module_config(cmd->server->module_config, &APMODULE);
	if (sconf==NULL)
		return "mod_icpquery not yet loaded";
	char* baseaddr;
	char* scope_id;
	apr_port_t port;
	apr_status_t rv = apr_parse_addr_port(&baseaddr, &scope_id, &port, peeraddr, cmd->pool);
	if (rv!=APR_SUCCESS || baseaddr==NULL)
		return apr_psprintf(cmd->pool, "Can't parse %s", peeraddr);
	if (port==0) port = ICPQUERYPORT;
	apr_sockaddr_t* icp_peeraddr;
	rv = apr_sockaddr_info_get(&icp_peeraddr, baseaddr, APR_INET, port, 0, cmd->pool);
	if (rv!=APR_SUCCESS)
		return apr_psprintf(cmd->pool, "%s:%d does not seem to be a valid IP address", baseaddr, port);
	*(apr_sockaddr_t**)apr_array_push(sconf->icp_peer_addrs) = icp_peeraddr;
	return NULL;
}

static
const char *cmd_mcastaddr(cmd_parms *cmd, void *dconf, const char *mcastaddr)
{
	const char *error;
	if ((error = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT)) != NULL)
		return error;
	icpquery_config *sconf = ap_get_module_config(cmd->server->module_config, &APMODULE);
	if (sconf==NULL)
		return "mod_icpquery not yet loaded";
	char* baseaddr;
	char* scope_id;
	apr_port_t port;
	apr_status_t rv = apr_parse_addr_port(&baseaddr, &scope_id, &port, mcastaddr, cmd->pool);
	if (rv!=APR_SUCCESS || baseaddr==NULL || port==0)
		return apr_psprintf(cmd->pool, "Can't parse %s", mcastaddr);
	if (port==0) port = ICPQUERYPORT;
	apr_sockaddr_t* icp_mcastaddr;
	rv = apr_sockaddr_info_get(&icp_mcastaddr, baseaddr, APR_INET, port, 0, cmd->pool);
	if (rv!=APR_SUCCESS)
		return apr_psprintf(cmd->pool, "%s:%d does not seem to be a valid multicast address", baseaddr, port);
	*(apr_sockaddr_t**)apr_array_push(sconf->icp_mcast_addrs) = icp_mcastaddr;
	return NULL;
}

static
const char *cmd_mcasthops(cmd_parms *cmd, void *dconf, const char *ttl)
{
	const char *error;
	if ((error = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT)) != NULL)
		return error;
	icpquery_config *sconf = ap_get_module_config(cmd->server->module_config, &APMODULE);
	if (sconf==NULL)
		return "mod_icpquery not yet loaded";
	int t = atoi(ttl);
	if (t<1 || t>255)
		return "ICPQueryMCastHops is allowed in the range 1...255";
	sconf->icp_mcasthops = t;
	return NULL;
}

static
const char *cmd_bindaddr(cmd_parms *cmd, void *dconf, const char *addr)
{
	const char *error;
	if ((error = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT)) != NULL)
		return error;
	icpquery_config *sconf = ap_get_module_config(cmd->server->module_config, &APMODULE);
	if (sconf==NULL)
		return "mod_icpquery not yet loaded";
	apr_status_t rv;
	if ((rv = apr_sockaddr_info_get(&sconf->icp_bindaddr, addr, APR_INET, 0, 0, cmd->pool))!=APR_SUCCESS)
		return apr_psprintf(cmd->pool, "Can't use %s as address to bind to", addr);
	return NULL;
}

static
const char *cmd_timeout(cmd_parms *cmd, void *dconf, const char *timeout)
{
	const char *error;
	if ((error = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT)) != NULL)
		return error;
	icpquery_config *sconf = ap_get_module_config(cmd->server->module_config, &APMODULE);
	if (sconf==NULL)
		return "mod_icpquery not yet loaded";
	int temp = atoi(timeout);
	sconf->icp_timeout = temp<0 ? 0 : temp;
	return NULL;
}

static
void register_hooks(apr_pool_t *p)
{
	static const char * const pre_modules[] = { "mod_rewrite.c", NULL };
	ap_hook_pre_config(pre_config, pre_modules, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_child_init(init_child, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec command_table[] =
{
	AP_INIT_FLAG(CONFIGURATIONPREFIX"Mapper", cmd_mapping_engine, NULL, RSRC_CONF,
	    "On or Off to enable or disable the internal "CONFIGURATIONPREFIX" mapper"),
	AP_INIT_TAKE1(CONFIGURATIONPREFIX"Log", cmd_logfile, NULL, RSRC_CONF,
	    "The filename of the "CONFIGURATIONPREFIX" log"),
	AP_INIT_TAKE1(CONFIGURATIONPREFIX"LogLevel", cmd_loglevel, NULL, RSRC_CONF,
	    "The level of the "CONFIGURATIONPREFIX" logfile verbosity, range is from 0 to 3"),
	AP_INIT_TAKE1(CONFIGURATIONPREFIX"Peer", cmd_peeraddr, NULL, RSRC_CONF,
	    "An internet address to send the "CONFIGURATIONPREFIX" as UDP unicast"),
	AP_INIT_TAKE1(CONFIGURATIONPREFIX"MCastAddr", cmd_mcastaddr, NULL, RSRC_CONF,
	    "The internet address to send an "CONFIGURATIONPREFIX" as UDP multicast"),
	AP_INIT_TAKE1(CONFIGURATIONPREFIX"MCastHops", cmd_mcasthops, NULL, RSRC_CONF,
	    "Set the Multicast Time to Live (ttl) for a multicast transmission"),
	AP_INIT_TAKE1(CONFIGURATIONPREFIX"BindAddr", cmd_bindaddr, NULL, RSRC_CONF,
	    "The local address to bind the "CONFIGURATIONPREFIX" sender"),
	AP_INIT_TAKE1(CONFIGURATIONPREFIX"Timeout", cmd_timeout, NULL, RSRC_CONF,
	    "Timeout in microseconds to wait for the latest ICP response"),
	{NULL}
};

module AP_MODULE_DECLARE_DATA APMODULE =
{
	STANDARD20_MODULE_STUFF,
	NULL,			// per-directory config creator
	NULL,			// dir config merger
	create_server_config,	// server config creator
	merge_server_config,	// merge_server_config
	command_table,		// command table
	register_hooks,		// set up other request processing hooks
};

