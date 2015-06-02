This page is for experts, knowing how to write Apache modules. This is a good starting point, if you want to implement your own mapping function.

## mod\_rewrite internals ##
mod\_icpquery offers mod\_rewrite two so named 'internal' [RewriteMap](http://httpd.apache.org/docs/2.2/mod/mod_rewrite.html#rewritemap) functions. In this context, 'internal' means a function part of the Apache's code. Until Apache version 2.0.36 these where limited to four internal mapping functions in mod\_rewrite. Since version 2.0.37 every Apache module may define its own mapping function and name it to whatever it likes. Such a function shall have a form such as:
```
static char *mapfoo(request_rec *req, char *key)
{
    // do the mapping
    return value;
}
```
where **req** is the Apache's internal request structure and **key** the string to map. The function shall return the mapped string, or NULL if no mapping is possible for the given key.

First add this code to the static section of an Apache module, in order to connect mod\_rewrite with that module:
```
typedef char *(rewrite_mapfunc_t)(request_rec *r, char *key);
APR_DECLARE_OPTIONAL_FN(void,
    ap_register_rewrite_mapfunc,
    (char *name, rewrite_mapfunc_t *func)
);
```

Now attach the mapping function to mod\_rewrite's [RewriteMap](http://httpd.apache.org/docs/2.2/mod/mod_rewrite.html#rewritemap) using this
code, preferably in the preconfig phase:
```
APR_OPTIONAL_FN_TYPE(ap_register_rewrite_mapfunc) *map_pfn_register;
map_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_rewrite_mapfunc);
if (map_pfn_register==NULL) {
    // report runtime error, mod_rewrite is not loaded into Apache
}
map_pfn_register(ICPQUERYMAPPER, mapfoo);
```