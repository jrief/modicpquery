
#define APR_WANT_MEMFUNC
#include <apr_want.h>
#include <apr_tables.h>

APR_DECLARE(apr_array_header_t *) 
apr_array_shuffle_ext(apr_pool_t * pool, apr_array_header_t * sorted)
{
    apr_array_header_t* shuffled = apr_array_make(pool, sorted->nelts, sorted->elt_size);
    if (shuffled==NULL) {
        // is it better to return an unshuffled array, than returning nothing?
        return sorted;
    }
    int nelts = shuffled->nelts = sorted->nelts;
    int elt_size = sorted->elt_size;
    int bufsize = elt_size * nelts;
    char buffer[bufsize];
    memcpy(buffer, sorted->elts, bufsize);
    char * shelts = shuffled->elts;
    unsigned int rnd;
    int i;
    for (i = 0; i<sorted->nelts; ++i) {
        apr_generate_random_bytes((unsigned char*)&rnd, sizeof(rnd));
        rnd %= nelts;
        memcpy(shelts, buffer + rnd*elt_size, elt_size);
        if (nelts-rnd>1)
            memmove(buffer+rnd*elt_size, buffer+(rnd+1)*elt_size, (nelts-rnd-1)*elt_size);
        --nelts;
        shelts += elt_size;
    }
    return shuffled;
}

