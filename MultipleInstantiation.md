## Instantiate mod\_icpquery more than once ##

Sometimes it can be necessary to have different mapping functions, for different kinds of application server clusters with different configuration parameters. Unfortunately, mod\_rewrite does not offer any way to parametrize the mapping function as specified using `ap_register_rewrite_mapfunc`.

The only feasible solution is to recompile the module using different names. When you have such a need, rebuild the module using
```
export ICPQUERYNAME=MyMap
./configure
make install
```
Set the environment variable ICPQUERYNAME to whatever you like, except `icpquery`. This will build and install a module with a different internal name and different configuration directives. In the above example, the configuration directives would look like
```
LoadModule      /path/to/apache/modules/mod_mymap.so
```
to load the newly build module.

```
MyMapMapper  [on|off]
```
to activate the newly build module.