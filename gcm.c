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
	temp_ctx->rk = (uint8_t*)malloc(sizeof(uint8_t)*160);
	if ( NULL == temp_ctx->rk ) { result = MBEDTLS_BLOCK_CIPHER_FAIL; }
	else { result = (temp_ctx->block_key_schedule)(temp_ctx->rk, (const uint8_t *)key);}
	return result;
}

void mbedtls_gcm_free( void *ctx ) {
	if ( ctx ) {
/* the ctx and ctx->rk point to the same place, so call free() one time is enough
		mbedtls_gcm_context *temp_ctx = (mbedtls_gcm_context*)ctx;
		if ( temp_ctx->rk ) {
			free((void*)(temp_ctx->rk));
		}
*/
		free(ctx);
	}
}

/* the const multi value */
static uint8_t H[16];

void printf_output(uint8_t *p) {
	uint8_t i = 0;
	for ( i = 0; i < BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
		printf("%x ", p[i]);
	}
	printf("\n");
}

/*
 * compute the value of x = x.h, where x and h all belong to GF(2^64)
 */
static void multi (uint8_t * x) {
	uint64_t z0 = 0, z1 = 0;

	uint64_t v0 = *(uint64_t *)x;
	uint64_t v1 = *((uint64_t *)x+1);

	uint64_t h0 = *(uint64_t *)H;
	uint64_t h1 = *((uint64_t *)H+1);

	uint8_t i = 0, j = 0;
	uint64_t temp = 0x8000000000000000;
	for ( i = 0; i < BLOCK_CIPHER_BLOCK_SIZE*4; i++ ) {
		if ( temp & h0 ) {
			z0 ^= v0;
			z1 ^= v1;
		}
		temp = temp >> 1;
		if ( v1 & 0x1 ) {
			v1 = v1 >> 1;
			if ( v0 & 0x1) { v1 ^= 0x8000000000000000;}
			v0 = v0 >> 1;
		} else {
			v1 = v1 >> 1;
			if ( v0 & 0x1) { v1 ^= 0x8000000000000000;}
			v0 = v0 >> 1;
			v0 ^= FIELD_CONST;
		}
	}
	for ( i = BLOCK_CIPHER_BLOCK_SIZE*4; i < BLOCK_CIPHER_BLOCK_SIZE*8; i++ ) {
		if ( temp & h0 ) {
			z0 ^= v0;
			z1 ^= v1;
		}
		temp = temp >> 1;
		if ( v1 & 0x1 ) {
			v1 = v1 >> 1;
			if ( v0 & 0x1) { v1 ^= 0x8000000000000000;}
			v0 = v0 >> 1;
		} else {
			v1 = v1 >> 1;
			if ( v0 & 0x1) { v1 ^= 0x8000000000000000;}
			v0 = v0 >> 1;
			v0 ^= FIELD_CONST;
		}
	}
	*(uint64_t *)x = v0;
	*((uint64_t *)x+1) = v1;
}

/**
 * return the value of vector after increasement
 * only input the vector of 96-bit
 */
static void incr (uint8_t *iv) {
	iv += 12;
	uint32_t temp = ((uint32_t)iv[0]<<24) + ((uint32_t)iv[1]<<16) + ((uint32_t)iv[2]<<8) + ((uint32_t)iv[3]) + 1;
	iv[3] = (uint8_t)temp;
	iv[2] = (uint8_t)temp>>8;
	iv[1] = (uint8_t)temp>>16;
	iv[0] = (uint8_t)temp>>24;
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
	int i = 0;
	for ( i = 0; i < add_len/BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
		*(uint64_t *)output ^= *(uint64_t *)add;
		*((uint64_t *)output+1) ^= *((uint64_t *)add+1);
		add += BLOCK_CIPHER_BLOCK_SIZE;
		multi(output);
	}
	// the remaining add
	for ( i = 0; i < add_len%BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
		*output ^= *add;
	}
	multi(output);

	/* compute with cipher text */
	for ( i = 0; i < length/BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
		*(uint64_t *)output ^= *(uint64_t *)cipher;
		*((uint64_t *)output+1) ^= *((uint64_t *)cipher+1);
		cipher += BLOCK_CIPHER_BLOCK_SIZE;
		multi(output);
	}
	// the remaining cipher
	for ( i = 0; i < length%BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
		*output ^= *cipher;
	}
	multi(output);

	/**/
	*(uint64_t *)output ^= (uint64_t)(add_len*8); // len(A) = (uint64_t)(add_len*8)
	*((uint64_t *)output+1) ^= (uint64_t)(length*8); // len(C) = (uint64_t)(length*8)
	multi(output);
}

/*
 * authenticated encryption
 *
 * suppose all the length is a multiple of BLOCK_SIZE
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

	uint8_t y0[BLOCK_CIPHER_BLOCK_SIZE] = {0};
	uint8_t ency0[BLOCK_CIPHER_BLOCK_SIZE];
	// set H
	(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, ency0);
	int i = 0;
	for ( i = 0; i < BLOCK_CIPHER_BLOCK_SIZE; i++ ) { H[i] = ency0[i]; }
	printf("H:      ");
	printf_output(H);

	// compute y0 (initilization vector)
	if (DEFAULT_IV_LEN == iv_len) {
		y0[0] = iv[0]; y0[1] =  iv[1]; y0[2] = iv[2]; y0[3] = iv[3];
		y0[4] = iv[4]; y0[5] =  iv[5]; y0[6] = iv[6]; y0[7] = iv[7];
		y0[8] = iv[8]; y0[9] =  iv[9]; y0[10] = iv[10]; y0[11] = iv[11];
		y0[12] = 0; y0[13] =  0; y0[14] = 0; y0[15] = 1;
	} else {
		ghash(NULL, 0, (const uint8_t*)iv, iv_len, y0);
	}
	printf("Y0:     ");
	for ( i = 0; i < BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
		printf("%x ", y0[i]);
	}
	printf("\n");


	// compute ency0 = ENC(K, y0)
	(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, ency0);
	printf("E(K, Y0): ");
	for ( i = 0; i < BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
		printf("%x ", ency0[i]);
	}
	printf("\n");


	/* encyrption */
	uint8_t * output_temp = output;
	for ( i = 0; i < length/BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
		incr(y0);
		// printf y(i+1)
		printf("Y%d:     ", i+1);
		printf_output(y0);

		(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, output);
		// printf enc(y(i+1))
		printf("E(K, Y%d): ", i+1);
		printf_output(output);

		*(uint64_t*)output ^= *(uint64_t*)input;
		*((uint64_t*)output+1) ^= *((uint64_t*)input+1);
		output += BLOCK_CIPHER_BLOCK_SIZE;
		input += BLOCK_CIPHER_BLOCK_SIZE;
	}
	// the remaining plain text
	if ( length % BLOCK_CIPHER_BLOCK_SIZE ) {
		incr(y0);
		(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, output);
		for ( i = 0; i < length%BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
			*output ^= *input;
		}
	}

	// printf cipher text
	printf("cipher: ");
	printf_output(output_temp);

	// compute tag, y0 is useless now
	ghash((const uint8_t *)add, add_len, (const uint8_t*)output_temp, length, y0);
	for ( i = 0; i < tag_len; i++ ) {
//		tag[i] = y0[BLOCK_CIPHER_BLOCK_SIZE-tag_len+i] ^ ency0[BLOCK_CIPHER_BLOCK_SIZE-tag_len+i];
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
