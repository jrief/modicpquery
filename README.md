# What is mod_icpquery?

Apache's ``mod_rewrite`` provides ways to map values to attributes using the directive ``RewriteMap``.
RewriteMap can use flat mappings files, hashed mapping files, internal functions and external
rewriting programs. One not well known feature of mod_rewrite is to extend this functionality with
internal functions, defined in a separate Apache module. This allows to do complex and time consuming
mappings, since the mapping request does not have to be passed through a single communication pipe, as
in the case of an external rewrite program.

## Internet Cache Protocol
``mod_icpquery`` is a package which can be used to find objects on caching servers by sending out a UDP
query. This query conforms to RFC2186 also known as ICP and can be handled by various caching servers
such as Squid. A cache server handling ICP should reply to an ICP-query with an ICP-response indicating
if it holds the desired object in its cache or not. mod_icpquery is able to send UDP datagrams to a list
of unicast and/or multicast IP-addresses.

## Getting started
Introduction and motivation for creating mod_icquery.
Installation: How to build and install mod_icquery.
Examples: Example setups for a typical usage of mod_icpquery.
ConfigurationDirectives: The reference manual for mod_icpquery.
MultipleInstantiation: In case you need the functionality for mod_icpquery more than once.
Internals: For experts, knowing how to write Apache modules, which want to write their own mapping functionality, in order to extend mod_rewrite.
