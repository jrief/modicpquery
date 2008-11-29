

#include <apr_pools.h>
#include "apr_ext.h"
#include <stdio.h>
#include <assert.h>

static
void print_array(apr_array_header_t * array)
{
	int i, k;
	int esize = array->elt_size;
	for (i = 0; i<array->nelts; ++i) {
		printf("[%d]: ", i);
		for (k = 0; k<esize; ++k)
			printf("%c", (unsigned int)array->elts[i*esize+k]);
		printf("\n");
	}
	printf("\n");
}

static
apr_array_header_t * build_sorted(apr_pool_t * pool, int start, int stop, int numbytes)
{
	int i, k;
	assert(stop>start);
	apr_array_header_t * sorted = apr_array_make(pool, stop-start, numbytes);
	for (i = start; i<stop; ++i) {
		char * c = (char*)apr_array_push(sorted);
		int k;
		for (k = 0; k<numbytes; ++k) {
			c[k] = i;
		}
	}
	return sorted;
}

int main(int argc, char** argv)
{
	apr_initialize();
	apr_pool_t * pool;
	apr_pool_create(&pool, NULL);

	apr_array_header_t * sorted = build_sorted(pool, 'a', 'a'+26, 1);
	print_array(sorted);
	apr_array_header_t * shuffled = apr_array_shuffle_ext(pool, sorted);
	print_array(shuffled);

	sorted = build_sorted(pool, 'A', 'A'+26, 5);
	print_array(sorted);
	shuffled = apr_array_shuffle_ext(pool, sorted);
	print_array(shuffled);
		
	return 0;
	
}

