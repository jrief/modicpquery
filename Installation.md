## Install mod\_icpquery ##
Ensure that the development headers and libraries for the Apache http daemon and the Apache Runtime Library are installed.

As root, change into to directory mod\_icpquery and run
```
./configure
make install
```
This should build the module and install it at the appropriate location. Users of operating systems which have rpm support, such as Redhat, Fedora, SuSe, CentOS, etc. may invoke
```
rpmbuild -tb mod_icpquery-_version_.tar.gz
```
to build the module as rpm package, which then may be installed using rpm.

After installing the module, Apache must be configured to load the module. Please read
the section [ConfigurationDirectives](ConfigurationDirectives.md).

## Fundamentals about extending mod\_rewrite ##
The [Apache manual](http://httpd.apache.org/docs/2.2/mod/mod_rewrite.html#rewritemap) explains: _"Currently you cannot create your own, but the following (ann. four) internal functions already exist, ..."_.

This is a documentation bug.

**mod\_icpquery** extends **mod\_rewrite** by two internal [RewriteMap](http://httpd.apache.org/docs/2.2/mod/mod_rewrite.html#rewritemap) functions

### icpquerymap ###
This function takes a URL as argument, which can be a html object which might be stored on a remote caching server. The function returns a semicolon separated list of all caching servers which replied to the caller, that they hold the requested object.

The function works by sending out an UDP query containing an [ICP](http://www.ietf.org/rfc/rfc2186.txt) request to one ore more UDP unicast and/or multicast addresses. If caching servers are configured to listen for ICP requests on those IP addresses, they shall reply to the querying host. According to the protocol specifications, a caching server containing the desired object, shall reply with the code **ICP\_HIT** to the asking server. If the server does not hold the object, it shall reply with **ICP\_MISS**.

### cacheisrunning ###
This function takes a hostname or IP address as key. If the caching server with that IP address recently answered with **ICP\_HIT** or **ICP\_MISS**, the function will return the key. Otherwise the function returns NULL.

In this context, "recently" means that **icpquerymap** must have been calledinside the same HTTP-request before this function has been called. Using this function, the caller can assure, that a request is forwarded to a cache server, which is guaranteed to run.