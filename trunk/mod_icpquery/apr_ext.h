
#include <apr_tables.h>

/**
 * Shuffle the content of an array.
 * @param p The pool to allocate the copy of the array out of.
 * @param sorted The sorted array.
 * @return An array of the same size with its elements shuffled randomly.
 **/
extern APR_DECLARE(apr_array_header_t *)
apr_array_shuffle_ext(apr_pool_t * pool,  const apr_array_header_t * sorted);

