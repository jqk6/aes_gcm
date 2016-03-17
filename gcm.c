/*
 *
 * Chinese Academy of Sciences
 * State Key Laboratory of Information Security, 
 * Institute of Information Engineering
 *
 * Copyright (C) 2016 Chinese Academy of Sciences
 *
 * Written in 2016
 *
 */

#include <stdint.h>
#include <stdlib.h>

#include "gcm.h"
#include "aes.h"

#define DEBUG (1)

void *mbedtls_gcm_init() {
	return malloc(sizeof(mbedtls_gcm_context));
}

/**
 * Just AES 128-128
 */
int mbedtls_gcm_setkey( void *ctx,
                        const unsigned char *key,
                        unsigned int keybits ) {
	if ( NULL == ctx ) { return MBEDTLS_BLOCK_CIPHER_FAIL; }
	int result = MBEDTLS_BLOCK_CIPHER_SUC ;
	mbedtls_gcm_context *temp_ctx = (mbedtls_gcm_context*)ctx;
	temp_ctx->block_key_schedule = (block_key_schedule_p)aes_key_schedule_128;
	temp_ctx->block_encrypt = (block_encrypt_p)aes_encrypt_128;
	temp_ctx->block_decrypt = (block_decrypt_p)aes_decrypt_128;
	temp_ctx->rk = (uint8_t*)malloc(sizeof(uint8_t)*ROUND_KEY_SIZE);
	if ( NULL == temp_ctx->rk ) { result = MBEDTLS_BLOCK_CIPHER_FAIL; }
	else { result = (temp_ctx->block_key_schedule)(temp_ctx->rk, (const uint8_t *)key);}
	return result;
}

void mbedtls_gcm_free( void *ctx ) {
	if ( ctx ) {
		mbedtls_gcm_context *temp_ctx = (mbedtls_gcm_context*)ctx;
		if ( temp_ctx->rk ) {
			free((void*)(temp_ctx->rk));
		}
		free(ctx);
	}
}

/* the const multi value */
static uint8_t H[16];

void printf_output(uint8_t *p, size_t length) {
	uint8_t i = 0;
	for ( i = 0; i < length; i++ ) {
		printf("%x ", p[i]);
	}
	printf("\n");
}

/*
 * compute the value of x = x.h, where x and h all belong to GF(2^64)
 */
static void multi (uint8_t * x) {

	uint64_t z0 = 0, z1 = 0;
	uint64_t v0 = ((uint64_t)x[0]<<56) + ((uint64_t)x[1]<<48) + ((uint64_t)x[2]<<40) + ((uint64_t)x[3]<<32) +
			((uint64_t)x[4]<<24) + ((uint64_t)x[5]<<16) + ((uint64_t)x[6]<<8) + ((uint64_t)x[7]);
	uint64_t v1 = ((uint64_t)x[8]<<56) + ((uint64_t)x[9]<<48) + ((uint64_t)x[10]<<40) + ((uint64_t)x[11]<<32) +
			((uint64_t)x[12]<<24) + ((uint64_t)x[13]<<16) + ((uint64_t)x[14]<<8) + ((uint64_t)x[15]);

	uint8_t temph;
	uint8_t i = 0, j = 0;
	uint64_t temp = 0x1;
	for ( i = 0; i < BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
		temph = H[i];
		for ( j = 0; j < 8; j++ ) {
			if ( 0x80 & temph ) {
				z0 ^= v0;
				z1 ^= v1;
			}
			if ( v1 & 0x1 ) {
				v1 = v1 >> 1;
				if ( v0 & 0x1) { v1 ^= 0x8000000000000000;}
				v0 = v0 >> 1;
				v0 ^= FIELD_CONST;
			} else {
				v1 = v1 >> 1;
				if ( v0 & 0x1) { v1 ^= 0x8000000000000000;}
				v0 = v0 >> 1;
			}
			temph = temph << 1;
		}
	}
	// get result
	for ( i = 1; i <= BLOCK_CIPHER_BLOCK_SIZE/2; i++ ) {
		x[BLOCK_CIPHER_BLOCK_SIZE/2-i] = (uint8_t)z0;
		z0 = z0 >> 8;
		x[BLOCK_CIPHER_BLOCK_SIZE-i] = (uint8_t)z1;
		z1 = z1 >> 8;
	}
}

/**
 * return the value of vector after increasement
 * only input the vector of 96-bit
 */
static void incr (uint8_t *iv) {
	iv += 12;
	uint32_t temp = ((uint32_t)iv[0]<<24) + ((uint32_t)iv[1]<<16) + ((uint32_t)iv[2]<<8) + ((uint32_t)iv[3]) + 1;
	iv[3] = (uint8_t)(temp); // the priority of () is higher than >>, ^_^
	iv[2] = (uint8_t)(temp>>8);
	iv[1] = (uint8_t)(temp>>16);
	iv[0] = (uint8_t)(temp>>24);
}

/*
 * a: additional authenticated data
 * c: the cipher text or initial vector
 */
static void ghash(const uint8_t *add, 
		size_t add_len,
		const uint8_t *cipher,
		size_t length,
		uint8_t *output) {
	/* x0 = 0 */
	*(uint64_t *)output = 0;
	*((uint64_t *)output+1) = 0;

	/* compute with add */
	int i = 0, j = 0;
	for ( i = 0; i < add_len/BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
		*(uint64_t *)output ^= *(uint64_t *)add;
		*((uint64_t *)output+1) ^= *((uint64_t *)add+1);
		add += BLOCK_CIPHER_BLOCK_SIZE;
		multi(output);
#if defined(DEBUG)
		printf("X+:             ");
		printf_output(output, BLOCK_CIPHER_BLOCK_SIZE);
#endif
	}

	if ( add_len % BLOCK_CIPHER_BLOCK_SIZE ) {
		// the remaining add
		for ( i = 0; i < add_len%BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
			*(output+i) ^= *(add+i);
		}
		multi(output);
#if defined(DEBUG)
		printf("X+:             ");
		printf_output(output, BLOCK_CIPHER_BLOCK_SIZE);
#endif
	}

	/* compute with cipher text */
	for ( i = 0; i < length/BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
		*(uint64_t *)output ^= *(uint64_t *)cipher;
		*((uint64_t *)output+1) ^= *((uint64_t *)cipher+1);
		cipher += BLOCK_CIPHER_BLOCK_SIZE;
		multi(output);
#if defined(DEBUG)
		printf("X+:             ");
		printf_output(output, BLOCK_CIPHER_BLOCK_SIZE);
#endif

	}
	if ( length % BLOCK_CIPHER_BLOCK_SIZE ) {
		// the remaining cipher
		for ( i = 0; i < length%BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
			*(output+i) ^= *(cipher+i);
		}
		multi(output);
#if defined(DEBUG)
		printf("X+:             ");
		printf_output(output, BLOCK_CIPHER_BLOCK_SIZE);
#endif
	}

	/* eor (len(A)||len(C)) */
	uint64_t temp_len = (uint64_t)(add_len*8); // len(A) = (uint64_t)(add_len*8)
	for ( i = 1; i <= BLOCK_CIPHER_BLOCK_SIZE/2; i++ ) {
		output[BLOCK_CIPHER_BLOCK_SIZE/2-i] ^= (uint8_t)temp_len;
		temp_len = temp_len >> 8;
	}
	temp_len = (uint64_t)(length*8); // len(C) = (uint64_t)(length*8)
	for ( i = 1; i <= BLOCK_CIPHER_BLOCK_SIZE/2; i++ ) {
		output[BLOCK_CIPHER_BLOCK_SIZE-i] ^= (uint8_t)temp_len;
		temp_len = temp_len >> 8;
	}
	multi(output);
}

/**
 * authenticated encryption
 */
int mbedtls_gcm_crypt_and_tag( void *ctx,
		const unsigned char *iv,
		size_t iv_len,
		const unsigned char *add,
		size_t add_len,
		const unsigned char *input,
		size_t length,
		unsigned char *output,
		unsigned char *tag,
		size_t tag_len) {

	mbedtls_gcm_context *temp_ctx = (mbedtls_gcm_context*)ctx;
	if ( !temp_ctx || !(temp_ctx->rk) ) { return MBEDTLS_BLOCK_CIPHER_FAIL; }
	if ( tag_len <= 0 || tag_len > BLOCK_CIPHER_BLOCK_SIZE ) { return MBEDTLS_BLOCK_CIPHER_FAIL; }

	uint8_t y0[BLOCK_CIPHER_BLOCK_SIZE] = {0}; // store the counter
	uint8_t ency0[BLOCK_CIPHER_BLOCK_SIZE]; // the cihper text of first counter

	/* set H */
	(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, ency0);
	int i = 0;
	for ( i = 0; i < BLOCK_CIPHER_BLOCK_SIZE; i++ ) { H[i] = ency0[i]; }

#if defined(DEBUG)
	printf("H:              ");
	printf_output(H, BLOCK_CIPHER_BLOCK_SIZE);
#endif

	/* compute y0 (initilization vector) */
	if (DEFAULT_IV_LEN == iv_len) {
		*(uint32_t*)y0 = *(uint32_t*)iv;
		*((uint32_t*)y0+1) = *((uint32_t*)iv+1);
		*((uint32_t*)y0+2) = *((uint32_t*)iv+2);
		y0[15] = 1;
	} else {
		ghash(NULL, 0, (const uint8_t*)iv, iv_len, y0);
	}

#if defined(DEBUG)
	printf("Y0:             ");
	printf_output(y0, BLOCK_CIPHER_BLOCK_SIZE);
#endif

	/* compute ency0 = ENC(K, y0) */
	(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, ency0);

#if defined(DEBUG)
	printf("E(K, Y0):       ");
	printf_output(ency0, BLOCK_CIPHER_BLOCK_SIZE);
#endif

	/* encyrption */
	uint8_t * output_temp = output; // store the start pointer of cipher text
	for ( i = 0; i < length/BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
		incr(y0);

#if defined(DEBUG)
		printf("Y%d:             ", i+1);
		printf_output(y0, BLOCK_CIPHER_BLOCK_SIZE);
#endif

		(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, output);

#if defined(DEBUG)
		printf("E(K, Y%d):       ", i+1);
		printf_output(output, BLOCK_CIPHER_BLOCK_SIZE);
#endif

		*(uint64_t*)output ^= *(uint64_t*)input;
		*((uint64_t*)output+1) ^= *((uint64_t*)input+1);
		output += BLOCK_CIPHER_BLOCK_SIZE;
	 	input += BLOCK_CIPHER_BLOCK_SIZE;
	}
	// the remaining plain text
	if ( length % BLOCK_CIPHER_BLOCK_SIZE ) {
		incr(y0);
#if defined(DEBUG)
		printf("Y+:             ");
		printf_output(y0, BLOCK_CIPHER_BLOCK_SIZE);
#endif
		// the last block size man be smaller than BLOCK_SIZE, can NOT be written directly.
//		(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, output);
		(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, y0);
#if defined(DEBUG)
		printf("E(K, Y+):       ");
		printf_output(y0, BLOCK_CIPHER_BLOCK_SIZE);
#endif
		for ( i = 0; i < length%BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
			*(output+i) = *(input+i) ^ *(y0+i);
		}
	}

#if defined(DEBUG)
	printf("cipher:         ");
	printf_output(output_temp, length);
#endif

	/* compute tag, y0 is useless now */
	ghash((const uint8_t *)add, add_len, (const uint8_t*)output_temp, length, y0);

#if defined(DEBUG)
	printf("GHASH(H, A, C): ");
	printf_output(y0, BLOCK_CIPHER_BLOCK_SIZE);
#endif

	for ( i = 0; i < tag_len; i++ ) {
		tag[i] = y0[i] ^ ency0[i];
	}
	return MBEDTLS_BLOCK_CIPHER_SUC;
}

/*
 * authenticated decryption
 */
int mbedtls_gcm_auth_decrypt( void *ctx,
              const unsigned char *iv,
              size_t iv_len,
              const unsigned char *add,
              size_t add_len,
              const unsigned char *tag,
              size_t tag_len,
              const unsigned char *input,
              size_t length,
              unsigned char *output ) {
	return MBEDTLS_BLOCK_CIPHER_SUC;
}
