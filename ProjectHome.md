## What is mod\_icpquery? ##
Apache's **mod\_rewrite** provides ways to map values to attributes using the directive [RewriteMap](http://httpd.apache.org/docs/2.2/mod/mod_rewrite.html#rewritemap). [RewriteMap](http://httpd.apache.org/docs/2.2/mod/mod_rewrite.html#rewritemap) can use flat mappings files, hashed mapping files, internal functions and external rewriting programs.
One not well known feature of **mod\_rewrite** is to extend this functionality with internal functions, defined in a separate Apache module. This allows to do complex and time consuming mappings, since the mapping request does not have to be passed through a single communication pipe, as in the case of an external rewrite program.

## Internet Cache Protocol ##
**mod\_icpquery** is a package which can be used to find objects on caching servers by sending out a UDP query. This query conforms to [RFC2186](http://www.ietf.org/rfc/rfc2186.txt) also known as ICP and can be handled by various caching servers such as [Squid](http://www.squid-cache.org/). A cache server handling ICP should reply to an ICP-query with an ICP-response indicating if it holds the desired object in its cache or not.
**mod\_icpquery** is able to send UDP datagrams to a list of unicast and/or multicast IP-addresses.

## Getting started ##
  * [Introduction](Introduction.md) and motivation for creating **mod\_icquery**.
  * [Installation](Installation.md): How to build and install **mod\_icquery**.
  * [Examples](Examples.md): Example setups for a typical usage of **mod\_icpquery**.
  * [ConfigurationDirectives](ConfigurationDirectives.md): The reference manual for **mod\_icpquery**.
  * [MultipleInstantiation](MultipleInstantiation.md): In case you need the functionality for **mod\_icpquery** more than once.
  * [Internals](Internals.md): For experts, knowing how to write Apache modules, which want to write their own mapping functionality, in order to extend **mod\_rewrite**.

Enjoy,
**Jacob Rief**