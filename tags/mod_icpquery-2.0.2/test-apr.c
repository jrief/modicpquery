

#include <apr_pools.h>
#include "apr_ext.h"
#include <stdio.h>

static
void print_array(apr_array_header_t * array)
{
	int i, k;
	int esize = array->elt_size;
	for (i = 0; i<array->nelts; ++i) {
		printf("[%d]:", i);
		for (k = 0; k<esize; ++k)
			printf(" 0x%x", (unsigned int)array->elts[i*esize+k]);
		printf("\n");
	}
	printf("\n");
}

int main(int argc, char** argv)
{
	apr_initialize();
	apr_pool_t * pool;
	apr_pool_create(&pool, NULL);
	apr_array_header_t * sorted = apr_array_make(pool, 26, 1);
	int i = 0;
	for (i = 0; i<26; ++i) {
		char * c = (char*)apr_array_push(sorted);
		*c = 'A'+i;
	}
	print_array(sorted);
	apr_array_header_t * shuffled = apr_array_shuffle_ext(pool, sorted);
	print_array(shuffled);

	sorted = apr_array_make(pool, 26, 3);
	i = 0;
	for (i = 0; i<26; ++i) {
		char * c = (char*)apr_array_push(sorted);
		c[0] = c[1] = c[2] = 'a'+i;
	}
	print_array(sorted);
	shuffled = apr_array_shuffle_ext(pool, sorted);
	print_array(shuffled);
		
	return 0;
	
}

