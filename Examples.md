﻿==An Example setup==
Typically, someone would run **mod\_icpquery** on an Apache together with **mod\_proxy\_balancer** or some other kind of application loadbalancing.

An Apache, in this configuration runs as a reverse proxy to distribute HTTP-traffic onto one or more upstream application servers. In situations, where it makes sense to cache the content generated by the application server, one can place a caching accelerator in front
of each application server. This is easier to configure, scales better and is more reliable, rather than passing all requests through a single caching server and distribute (ie. loadbalance) them afterwards.

A good caching server is [Squid](http://www.squid-cache.org), as it has an Open Source License and has a small footprint.

The problem, with a distributed cache is, that the balancing proxy somehow has to know, which cache holds which object. This is where **mod\_icpquery** becomes part of the game.

![http://modicpquery.googlecode.com/svn/wiki/diagram.jpeg](http://modicpquery.googlecode.com/svn/wiki/diagram.jpeg)

  1. Apache sends an ICP request via UDP multicast to all of the application servers. This is shown by a dotted line.
  1. If the squid cache running in front of the application server, say 192.168.0.1, replies to this request, the originating HTTP request is passed to the caching server, ie. port 3128. It does not matter, whether the cache replied with **ICP\_HIT** or **ICP\_MISS**. If however, **mod\_icpquery** did not receive any ICP reply (a strong indication that the squid cache does not run), the HTTP request is forwarded directly to the application service, ie. port 8001, shown as 2'.
  1. In case, squid cache does not hold the requested object, the request is forwarded to the application server running on the local host.

### Configure mod\_rewrite to take advantage of mod\_icpquery ###
When **mod\_icpquery** is loaded into Apache, two additional functions become available as internal [RewriteMap](http://httpd.apache.org/docs/2.2/mod/mod_rewrite.html#rewritemap)'s. An example configuration is shown below.

An Apache portal server shall forward all dynamic requests starting with /wsgi/ to a cluster of three application servers. All static requests shall be handled by the portal server itself. The application servers have the IP addresses 192.168.0.1, 192.168.0.2 and
192.168.0.3 respectively. Their application service listens on port 8001.

On each of those hosts, an additional squid server is running in acceleration mode listening on port 3128. All requests reaching one of those hosts on port 3128 are delivered from the local cache, or forwarded transparently onto the application service. Note that the portal server must ensure, that requests are only forwarded to running services, and as we all know, they might be down for whatever reasons.

### Configure Squid-Cache as http-accelerator ###
only the relevant configuration options are shown
```
# Squid-Cache shall listen on port TCP/3128 and run in acceleration mode.
http_port 3128 accel defaultsite=localhost

# All incoming requests shall be forward onto the application server,
# which is running on the same host and listens on port TCP/8001.
cache_peer 127.0.0.1 parent 8001 0 no-query originserver

# Squid-Cache shall listen for ICP requests on port UDP/3130
icp_port 3130

# Create an ACL for 'all' IP-addresses
acl all src 0.0.0.0/0.0.0.0

# Allow ICP requests from 'all' IP-addresses
icp_access allow all
```

### Configure Apache to take advantage of mod\_icpquery ###
only the relevant configuration options are shown
```
# Load the Apache module and activate the mapper
LoadModule icpquery_module modules/mod_icpquery.so
ICPQueryMapper			on

# The time to wait for ICP replies (in microseconds)
ICPQueryTimeout                 50000

# The logfile and the log-level to log events from mod_icpquery
ICPQueryLog                     /var/log/httpd/icpquery.log
# Start with a loglevel of 3 during setup, decrease it to 1 or 0 during production
ICPQueryLogLevel                3

# Specify the NIC from which ICP-queries are send from
# this is useful, in case the host has more than one NIC
#ICPQueryBindAddr                myhostname

# One or more IP addresses to send the ICP query as UDP unicastcast
ICPQueryPeer            192.168.0.1:3130
ICPQueryPeer            192.168.0.2:3130
ICPQueryPeer            192.168.0.3:3130

# As an alternative, one or more IP addresses to send the ICP query
# as UDP multicast. Read the manual to understand what to use in which
# situation
#ICPQueryMCastAddr       238.255.255.253:3130

# Use mod_proxy_balancer to distribute requests starting with /wsgi to three
# application servers (192.168.0.1, 192.168.0.2 and 192.168.0.3), all listening 
# on port 8001
<Proxy balancer://mycluster>
    BalancerMember http://192.168.0.1:8001
    BalancerMember http://192.168.0.2:8001
    BalancerMember http://192.168.0.3:8001
</Proxy>
ProxyPass               /wsgi/               balancer://mycluster/wsgi/

# Enable mod_rewrite
RewriteEngine       On
RewriteLog          /var/log/httpd/rewrite.log
# Start with a loglevel of 5 during setup, decrease it to 1 or 0 during production
RewriteLogLevel	    5

# Define a mapping file where all the upstream servers are specified
# this file shall look like the sample `proxies.txt`
RewriteMap          upstreamproxy            rnd:/etc/httpd/proxies.txt

# Import the two additional internal mapping functions as defined by mod_icpquery
RewriteMap          icpquery                 int:icpquerymap
RewriteMap          cacheisrunning           int:icpqueryisrunning

# store the query string in an environment variable if it exists
# to be appended at the mapping function `icpquery'
RewriteCond         %{QUERY_STRING}          ^(.+)$
RewriteRule         .*                       -  [env=QUERYSTRING:?%1]

# check if any squid accelerator can find the object in its local
# cache and if so, pass the request directly to that squid-cache
RewriteCond         ${icpquery:http://localhost$1%{ENV:QUERYSTRING}}  ^([^;]+);
RewriteRule         ^(/wsgi/.+)$             http://%1:3128$1  [proxy,last]

# otherwise, randomly choose a squid accelerator from the list upstreamproxy,
# check if it is up and running and if so forward the request to this server
RewriteCond         ${upstreamproxy:squids}  ^(.+)$
RewriteCond         ${cacheisrunning:%1}     ^(.+)$
RewriteRule         ^(/wsgi/.+)$             http://%1:3128$1  [proxy,last]

# otherwise, requests which shall be handled by the application servers
# are passed through to mod_proxy_balancer
RewriteRule         ^(/wsgi/.+)$             -  [passthrough]

# static requests are handled on this tier
RewriteRule         ^(.*)$                   %{DOCUMENT_ROOT}$1  [last]
```

The mapping file **/etc/httpd/proxies.txt** contains a list of upstream servers.
The [RewriteMap](http://httpd.apache.org/docs/2.2/mod/mod_rewrite.html#rewritemap)
```
squids 192.168.0.1|192.168.0.2|192.168.0.3
```