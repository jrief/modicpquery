## Configuration directives ##
In the global section of the Apache's configuration, load the module
```
LoadModule      /path/to/apache/modules/mod_icpquery.so
```

In the global, virtual server or directory server's context, define the external parameters for
```
ICPQueryMapper  [on|off]
```

After **icpquerymap** has send out a request, it will wait for at maximum this time until the caching servers replied. A timeout which is too high, will result in unnecessary delay. If it is too short, it increases the probability of missing an useful ICP-reply.
```
ICPQueryTimeout <time in microseconds>
```

Define the name of the debugging logfile for this module.
```
ICPQueryLog     </logpath/to/httpd/icpquery.log>
```

Define the logging level for this module. Logleves are:
**0 = Log all kind of problems.**  1 = Log the final result as delivered to the corresponding RewriteMap
**2 = Log informative messages**  3 = Debug logging
```
ICPQueryLogLevel   <loglevel>
```

Define a hostname or peer address and its port listening for ICP requests.
```
ICPQueryPeer   <peer>:<port>
```
If this configuration option is specified more than once, an ICP request is sent out to each of the specified addresses.

Define a multicast address and its port listening for ICP requests.
```
ICPQueryMCastAddr   <multicastaddr>:<port>
```
If this configuration option is specified more than once, an ICP request is sent out to each of the specified addresses.

Limit the spreading of ICP datagrams, sent using multicast.
```
ICPQueryMCastHops   <ttl>
```
Each router decreases the multicast TTL by one count. If the TTL
reaches zero, the datagram is not forwarded anymore.