dnl Configuration script for mod_icpquery
dnl Process this file with autoconf to produce a configure script.
dnl Copyright 2008 Jacob Rief

AC_INIT(mod_icpquery)
VERSION="`cat VERSION`"
REVISION="${VERSION}-`svnversion`"
OUTPUT_TARGET="Makefile defaults.h mod_icpquery.spec"

AC_ARG_WITH(apxs, AC_HELP_STRING([--with-apxs=NAME],
        [name of the apxs executable [[apxs]]]),
        [APXS="$with_apxs"])

AC_ARG_WITH(icp-query-port, AC_HELP_STRING([--with-icp-query-port=PORT],
	[define port to send ICP queries to, default is 3130]),
	[ICPQUERYPORT=$with_icp_query_port], [ICPQUERYPORT=3130])

AC_ARG_VAR(ICPQUERYNAME, [This name specifies: (I) the configuration prefix prepended 
	in front of the mapper modules configurations, the default is 'ICPQuery'.
	(II) the internal Apache rewrite function as used by RewriteMap to query for
	cached objects, the default is 'icpquerymap'. (III) the internal Apache rewrite 
	function as used by RewriteMap to query for caching servers which recently
	have demonstrated to be alive, the default is 'icpqueryisrunning'.
	(IV) the name of the module as used by the LoadModule configuration directive
	offered by Apache, default is 'icpquery_module'. (V) the name of the shared object
	generated as output, default is 'mod_icpquery.so'. Reconfigure this only in situations
	where you must load mod_icpquery more than once in order to instantiate
	queries for more than one group of caches])

if test -z "${APXS}"; then
        AC_PATH_PROGS(APXS, apxs2 apxs, [apxs], [$PATH:/usr/local/apache/bin:/usr/sbin])
fi

if test -z "${ICPQUERYNAME}"; then
	CONFIGURATIONPREFIX="ICPQuery"
	ICPQUERYNAME="icpquery"
else
	CONFIGURATIONPREFIX="${ICPQUERYNAME}"
	ICPQUERYNAME="$(echo $ICPQUERYNAME | awk '{ print tolower($1) }')"
fi
ICPQUERYMAPPER="${ICPQUERYNAME}map"
CHECKCACHEMAPPER="${ICPQUERYNAME}isrunning"
APMODULENAME="${ICPQUERYNAME}_module"
SOMODULENAME="mod_${ICPQUERYNAME}"

AC_SUBST(APXS)
AC_SUBST(REVISION)
AC_SUBST(VERSION)
AC_SUBST(ICPQUERYPORT)
AC_SUBST(ICPQUERYMAPPER)
AC_SUBST(CHECKCACHEMAPPER)
AC_SUBST(CONFIGURATIONPREFIX)
AC_SUBST(APMODULENAME)
AC_SUBST(SOMODULENAME)

AC_MSG_CHECKING(Apache version)
HTTPD="`${APXS} -q SBINDIR`/`${APXS} -q TARGET`"
HTTPD_VERSION=`$HTTPD -v | awk '/version/ {print $3}' | awk -F/ '{print $2}'`
AC_MSG_RESULT($HTTPD_VERSION)

dnl check for Apache 2.0.37 or later
HTTPD_MAJOR_VERSION=`echo ${HTTPD_VERSION} | cut -d '.' -f1`
HTTPD_MINOR_VERSION=`echo ${HTTPD_VERSION} | cut -d '.' -f2`
HTTPD_PATCH_VERSION=`echo ${HTTPD_VERSION} | cut -d '.' -f3`
if test ${HTTPD_MAJOR_VERSION} -lt 2 -o ${HTTPD_MINOR_VERSION} -eq 0 -a ${HTTPD_PATCH_VERSION} -le 37; then
	AC_MSG_ERROR([mod_icpquery can only be compiled with Apache 2.0.37 or later])
fi 

CPPFLAGS=""

CFLAGS=""
if test -x /usr/bin/lipo; then
    LDFLAGS3=""
    ARCHITECTURES=`/usr/bin/lipo -info $HTTPD | sed -e 's/.*://'`
    for ARCH in $ARCHITECTURES; do
        CFLAGS="${CFLAGS} -Wc,'-arch ${ARCH}'" 
        LDFLAGS3="${LDFLAGS3} -arch ${ARCH}" 
    done
    LDFLAGS="${LDFLAGS3} ${LDFLAGS}"
fi

AC_SUBST(CPPFLAGS)
AC_SUBST(CFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(LDLIBS)

LIBEXECDIR="`${APXS} -q LIBEXECDIR`"
AC_SUBST(LIBEXECDIR)

AC_OUTPUT($OUTPUT_TARGET)

AC_MSG_NOTICE([

Configuration for Apache RewriteMap internal function extensions
------------------------
Apache module name:                        ${APMODULENAME}
Shared object name:                        ${SOMODULENAME}.so
Revision:                                  ${REVISION}
ICP query port:                            ${ICPQUERYPORT}
Function name of ICP query mapper:         ${ICPQUERYMAPPER} 
Function name to check for running caches: ${CHECKCACHEMAPPER} 
Apache's configuration prefix:             ${CONFIGURATIONPREFIX} 
])

