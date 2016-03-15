
#include <stdio.h>
#include <stdlib.h>

#include "aes.h"
#include "gcm.h"

int main(int argc, char *argv[]) {

	uint8_t i;
	 
	/* 128 bits */
	uint8_t key[16] = {0};

	uint8_t iv[12] = {0};
	size_t iv_len = 12;
	
	uint8_t *add = NULL;
	size_t add_len = 0;

	uint8_t input[16] = {0};
	uint8_t output[16];
	size_t length = 16;

	uint8_t tag[16] = {0};
	size_t tag_len = 16;
	
	void * context = mbedtls_gcm_init();
	if ( !context ) { 
		printf("malloc failed.\n");
		return 0;
	}
	
	int flag = -2;
	flag = mbedtls_gcm_setkey( context, (const unsigned char *)key, 128 );

	if ( MBEDTLS_BLOCK_CIPHER_FAIL != flag ) {
		mbedtls_gcm_crypt_and_tag( context,
			(const unsigned char *)iv,
			iv_len,
			(const unsigned char *)add,
			add_len,
			(const unsigned char *)input,
			length,
			(unsigned char *)output,
			(unsigned char *)tag,
			tag_len);

		printf("Tag:\n");
		for (i = 0; i < 4; i++) {
			printf("%x %x %x %x ", tag[4*i+0], tag[4*i+1], tag[4*i+2], tag[4*i+3]);
		}
		printf("\n");
	}

	mbedtls_gcm_free( context);

	return 0;

}
