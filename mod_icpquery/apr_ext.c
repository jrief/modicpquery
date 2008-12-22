
#define APR_WANT_MEMFUNC
#include <apr_want.h>
#include <apr_tables.h>

APR_DECLARE(apr_array_header_t *) 
apr_array_shuffle_ext(apr_pool_t * pool, apr_array_header_t * sorted)
{
    apr_array_header_t* shuffled = apr_array_make(pool, sorted->nelts, sorted->elt_size);
    if (shuffled==NULL) {
	// in case malloc failed, is it better to return an unshuffled array, rather than null?
        return sorted;
    }
    shuffled->nelts = sorted->nelts;
    int elt_size = sorted->elt_size;
    char * base = shuffled->elts;
    memcpy(base, sorted->elts, elt_size * sorted->nelts);
    int nelts;
    for (nelts = sorted->nelts; nelts>0; --nelts) {
        unsigned int rnd;
        apr_generate_random_bytes((unsigned char*)&rnd, sizeof(rnd));
        rnd %= nelts;
        char * randpos = base + rnd*elt_size;
        char swapbuf[elt_size];
        memcpy(swapbuf, base, elt_size);
        memcpy(base, randpos, elt_size);
        memcpy(randpos, swapbuf, elt_size);
        base += elt_size;
    }
    return shuffled;
}

