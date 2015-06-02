## Introduction ##
Apache's [mod\_rewrite](http://httpd.apache.org/docs/2.2/mod/mod_rewrite.html) provides methods to map values to attributes using the directive [RewriteMap](http://httpd.apache.org/docs/2.2/mod/mod_rewrite.html#rewritemap). One not so well known feature of **mod\_rewrite** is to extend this functionality with internal functions, which can be defined in a seperate Apache module.

**mod\_icpquery** is an Apache-2.0/2.2 compatible module which extends **mod\_rewrite** by internal [RewriteMap](http://httpd.apache.org/docs/2.2/mod/mod_rewrite.html#rewritemap) functions. It sends out a request as UDP query to a list of unicast or multicast addresses. This query conforms to [RFC2186](http://www.ietf.org/rfc/rfc2186.txt) also known as ICP and can be handled by various HTTP-caching servers such as [squid](http://www.squid-cache.org). A cache-server handling ICP should reply to an ICP-query with an ICP-response indicating if it holds the desired object in its cache or not. This information can be further processed by mod\_rewrite using its superb regex rules.

Apache's **mod\_rewrite** is an excellent module to build up a web application server environment, it offers all the flexibility needed. One of the most useful feature offered by the directive [RewriteMap](http://httpd.apache.org/docs/2.2/mod/mod_rewrite.html#rewritemap) are all kinds of lookups, with their variants **txt:** (for plain text lookups), **dbm:** (for Berkeley styled database lookups), **int:** (for internal rewriting functions) and **prg:** (for an external rewriting programm).

The most flexible mapping functionality can be achieved with the external rewrite program (prefixed with **prg:**), which however has a big drawback as mentioned in the Apache documentation:
> But be very careful:
> > ``Keep it simple, stupid'' (KISS). If this program hangs, it will
> > cause Apache to hang when trying to use the relevant rewrite rule."
This is because an external rewrite program is instantiated only once, and all Apache child processes must communicate with this program through only one bidirectional pipe. Therefore such a program is not suitable to perform tasks, with unpredictable response times, such as database lookups.

On the other side, internal mapping functions (prefixed with **int:**) can be run concurrently, as they are executed inside each of their Apache child processes. Unfortunately internal [RewriteMap](http://httpd.apache.org/docs/2.2/mod/mod_rewrite.html#rewritemap) functions where available only to **mod\_rewrite**, limiting them to: **toupper**, **tolower**, **escape** and **unescape**. Finally, in Apache-2.0.37 this long awaited feature was introduced:

> Added an optional function (ap\_register\_rewrite\_mapfunc) which allows
> third-party modules to extend mod\_rewrite's "int:" internal [RewriteMap](http://httpd.apache.org/docs/2.2/mod/mod_rewrite.html#rewritemap)
> functionality.
However, until now there is no documentation on how to use this feature to extend
**mod\_rewrite** by a customized internal mapping function. **mod\_icpquery** can be used as example code to extend your lookup problem, where an external rewrite program may cause trouble.