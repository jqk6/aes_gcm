/*
 *
 * Chinese Academy of Sciences
 * State Key Laboratory of Information Security, 
 * Institute of Information Engineering
 *
 * Copyright (C) 2016 Chinese Academy of Sciences
 *
 * LuoPeng(luopeng@iie.ac.cn)
 * XiangZejun(xiangzejun@iie.ac.cn)
 *
 * Updated in May 2016
 *
 */

#include <stdint.h>
#include <stdlib.h>

#include "gcm.h"
#include "aes.h"

#define DEBUG (1)

void *gcm_init() {
    return malloc(sizeof(gcm_context));
}

int gcm_setkey( void *ctx,
    const unsigned char *key,
    unsigned int keybits ) {
    if ( NULL == ctx ) { return BLOCK_CIPHER_FAIL; }
    gcm_context *temp_ctx = (gcm_context*)ctx;
    temp_ctx->block_key_schedule = (block_key_schedule_p)aes_key_schedule_128;
    temp_ctx->block_encrypt = (block_encrypt_p)aes_encrypt_128;
    temp_ctx->block_decrypt = (block_decrypt_p)aes_decrypt_128;
    temp_ctx->rk = (uint8_t*)malloc(sizeof(uint8_t)*ROUND_KEY_SIZE);
    if ( NULL == temp_ctx->rk ) { return BLOCK_CIPHER_FAIL; }
    temp_ctx->block_key_schedule((const uint8_t *)key, temp_ctx->rk);
    return BLOCK_CIPHER_SUC;
}

void gcm_free( void *ctx ) {
    if ( ctx ) {
        gcm_context *temp_ctx = (gcm_context*)ctx;
        if ( temp_ctx->rk ) {
            free((void*)(temp_ctx->rk));
        }
        free(ctx);
    }
}

/**
 * compute T1, T2, ... , and T15
 * suppose 0^n is a string with n bit zeros, s1||s2 is a jointed string of s1 and s2
 * 
 * T1 = T0 . P^8
 * 	where P^8 = 0^8 || 1 || 0^119
 * T2 = T1 . P^8 = T0 . P^16
 * 	where P^16 = 0^16 || 1 || 0^111
 * T3 = T2 . P^8 = T0 . P^24
 * ...
 * T15 = T14 . P^8 = T0 . P^120
 * 	where P^120 = 0^120 || 1 || 0^7
 *
 */
static void otherT(uint8_t T[][256][16]) {
	int i = 0, j = 0, k = 0;
	uint64_t vh, vl;
	uint64_t zh, zl;
	for ( i = 0; i < 256; i++ ) {
		vh = ((uint64_t)T[0][i][0]<<56) ^ ((uint64_t)T[0][i][1]<<48) ^ ((uint64_t)T[0][i][2]<<40) ^ ((uint64_t)T[0][i][3]<<32) ^
			((uint64_t)T[0][i][4]<<24) ^ ((uint64_t)T[0][i][5]<<16) ^ ((uint64_t)T[0][i][6]<<8) ^ ((uint64_t)T[0][i][7]);
		vl = ((uint64_t)T[0][i][8]<<56) ^ ((uint64_t)T[0][i][9]<<48) ^ ((uint64_t)T[0][i][10]<<40) ^ ((uint64_t)T[0][i][11]<<32) ^
			((uint64_t)T[0][i][12]<<24) ^ ((uint64_t)T[0][i][13]<<16) ^ ((uint64_t)T[0][i][14]<<8) ^ ((uint64_t)T[0][i][15]);
		zh = zl = 0;
		for ( j = 0; j <= 120; j++ ) {
			if ( (j > 0) && (0 == j%8) ) {
				zh ^= vh;
				zl ^= vl;
				for ( k = 1; k <= BLOCK_CIPHER_BLOCK_SIZE/2; k++ ) {
					T[j/8][i][BLOCK_CIPHER_BLOCK_SIZE/2-k] = (uint8_t)zh;
					zh = zh >> 8;
					T[j/8][i][BLOCK_CIPHER_BLOCK_SIZE-k] = (uint8_t)zl;
					zl = zl >> 8;
				}
				zh = zl = 0;
			}
			if ( vl & 0x1 ) {
				vl = vl >> 1;
				if ( vh & 0x1) { vl ^= 0x8000000000000000;}
				vh = vh >> 1;
				vh ^= FIELD_CONST;
			} else {
				vl = vl >> 1;
				if ( vh & 0x1) { vl ^= 0x8000000000000000;}
				vh = vh >> 1;
			}
		}
	}
}

/**
 * @purpose
 * compute table T0 = X0 . H
 * only the first byte of X0 is nonzero, other bytes are all 0
 * @T
 * the final tables: 16 tables in total, each has 256 elements, the value of which is 16 bytes
 * @H
 * 128-bit, H = E(K, 0^128)
 * the leftmost(most significant) bit of H[0] is bit-0 of H(in GCM)
 * the rightmost(least significant) bit of H[15] is bit-127 of H(in GCM)
 */
static void computeTable (uint8_t T[][256][16], uint8_t H[]) {

	// zh is the higher 64-bit, zl is the lower 64-bit
	uint64_t zh = 0, zl = 0;
	// vh is the higher 64-bit, vl is the lower 64-bit
	uint64_t vh = ((uint64_t)H[0]<<56) ^ ((uint64_t)H[1]<<48) ^ ((uint64_t)H[2]<<40) ^ ((uint64_t)H[3]<<32) ^
			((uint64_t)H[4]<<24) ^ ((uint64_t)H[5]<<16) ^ ((uint64_t)H[6]<<8) ^ ((uint64_t)H[7]);
	uint64_t vl = ((uint64_t)H[8]<<56) ^ ((uint64_t)H[9]<<48) ^ ((uint64_t)H[10]<<40) ^ ((uint64_t)H[11]<<32) ^
			((uint64_t)H[12]<<24) ^ ((uint64_t)H[13]<<16) ^ ((uint64_t)H[14]<<8) ^ ((uint64_t)H[15]);
	uint8_t temph;

	uint64_t tempvh = vh;
	uint64_t tempvl = vl;
	int i = 0, j = 0;
	for ( i = 0; i < 256; i++ ) {
		temph = (uint8_t)i;
		vh = tempvh;
		vl = tempvl;
		zh = zl = 0;

		for ( j = 0; j < 8; j++ ) {
			if ( 0x80 & temph ) {
				zh ^= vh;
				zl ^= vl;
			}
			if ( vl & 0x1 ) {
				vl = vl >> 1;
				if ( vh & 0x1) { vl ^= 0x8000000000000000;}
				vh = vh >> 1;
				vh ^= FIELD_CONST;
			} else {
				vl = vl >> 1;
				if ( vh & 0x1) { vl ^= 0x8000000000000000;}
				vh = vh >> 1;
			}
			temph = temph << 1;
		}
		// get result
		for ( j = 1; j <= BLOCK_CIPHER_BLOCK_SIZE/2; j++ ) {
			T[0][i][BLOCK_CIPHER_BLOCK_SIZE/2-j] = (uint8_t)zh;
			zh = zh >> 8;
			T[0][i][BLOCK_CIPHER_BLOCK_SIZE-j] = (uint8_t)zl;
			zl = zl >> 8;
		}
	}
	otherT(T);
}

/**
 * return the value of (output.H) by looking up tables
 */
static void multi(uint8_t T[][256][16], uint8_t *output) {
	uint8_t i, j;
	uint8_t temp[16];
	for ( i = 0; i < 16; i++ ) {
		temp[i] = output[i];
		output[i] = 0;
	}
	for ( i = 0; i < 16; i++ ) {
		for ( j = 0; j < 16; j++ ) {
			output[j] ^= T[i][*(temp+i)][j];
		}
	}
}

/**
 * return the value of vector after increasement
 */
static void incr (uint8_t *iv) {
	iv += 12;
	uint32_t temp = ((uint32_t)iv[0]<<24) + ((uint32_t)iv[1]<<16) + ((uint32_t)iv[2]<<8) + ((uint32_t)iv[3]) + 1;
	iv[3] = (uint8_t)(temp); // the priority of () is higher than >>, ^_^
	iv[2] = (uint8_t)(temp>>8);
	iv[1] = (uint8_t)(temp>>16);
	iv[0] = (uint8_t)(temp>>24);
}

#if defined(DEBUG)
static int countY = 0;

static void printf_output(uint8_t *p, size_t length) {
	uint8_t i = 0, j = 0;
	if ( length > BLOCK_CIPHER_BLOCK_SIZE) {
		// first block
		for ( i = 0; i < BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
			printf("%2x ", p[i]);
		}
		printf("\n");
		// middle blocks
		for ( i = 1; i < length/BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
			printf("                ");
			for ( j = 0; j < BLOCK_CIPHER_BLOCK_SIZE; j++ ) {
				printf("%2x ", p[i*BLOCK_CIPHER_BLOCK_SIZE+j]);
			}
			printf("\n");
		}
		// last block
		printf("                ");
		i = length/BLOCK_CIPHER_BLOCK_SIZE*BLOCK_CIPHER_BLOCK_SIZE;
		for ( ; i < length; i++ ) {
			printf("%2x ", p[i]);
		}
		printf("\n");
	} else {
		for ( i = 0; i < length; i++ ) {
			printf("%2x ", p[i]);
		}
		printf("\n");
	}
}
#endif

/*
 * a: additional authenticated data
 * c: the cipher text or initial vector
 */
static void ghash(uint8_t T[][256][16],
		const uint8_t *add, 
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
		multi(T, output);
	}

	if ( add_len % BLOCK_CIPHER_BLOCK_SIZE ) {
		// the remaining add
		for ( i = 0; i < add_len%BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
			*(output+i) ^= *(add+i);
		}
		multi(T, output);
	}

	/* compute with cipher text */
	for ( i = 0; i < length/BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
		*(uint64_t *)output ^= *(uint64_t *)cipher;
		*((uint64_t *)output+1) ^= *((uint64_t *)cipher+1);
		cipher += BLOCK_CIPHER_BLOCK_SIZE;
		multi(T, output);
	}
	if ( length % BLOCK_CIPHER_BLOCK_SIZE ) {
		// the remaining cipher
		for ( i = 0; i < length%BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
			*(output+i) ^= *(cipher+i);
		}
		multi(T, output);
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
	multi(T, output);
}

/**
 * authenticated encryption
 */
int gcm_crypt_and_tag( void *ctx,
		const unsigned char *iv,
		size_t iv_len,
		const unsigned char *add,
		size_t add_len,
		const unsigned char *input,
		size_t length,
		unsigned char *output,
		unsigned char *tag,
		size_t tag_len) {

	gcm_context *temp_ctx = (gcm_context*)ctx;
	if ( !temp_ctx || !(temp_ctx->rk) ) { return BLOCK_CIPHER_FAIL; }
	if ( tag_len <= 0 || tag_len > BLOCK_CIPHER_BLOCK_SIZE ) { return BLOCK_CIPHER_FAIL; }

	uint8_t y0[BLOCK_CIPHER_BLOCK_SIZE] = {0}; // store the counter
	uint8_t ency0[BLOCK_CIPHER_BLOCK_SIZE]; // the cihper text of first counter

	/* set H */
	(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, ency0);
	int i = 0;
	for ( i = 0; i < BLOCK_CIPHER_BLOCK_SIZE; i++ ) { temp_ctx->H[i] = ency0[i]; }

#if defined(DEBUG)
	printf("\n----AUTH-ENCRYPTION----\n");
	printf("COMPUTE TABLES\n");
#endif
	computeTable(temp_ctx->T, temp_ctx->H);

#if defined(DEBUG)
	printf("H:              ");
	printf_output(temp_ctx->H, BLOCK_CIPHER_BLOCK_SIZE);
#endif

	/* compute y0 (initilization vector) */
	if (DEFAULT_IV_LEN == iv_len) {
		*(uint32_t*)y0 = *(uint32_t*)iv;
		*((uint32_t*)y0+1) = *((uint32_t*)iv+1);
		*((uint32_t*)y0+2) = *((uint32_t*)iv+2);
		y0[15] = 1;
	} else {
		ghash(temp_ctx->T, NULL, 0, (const uint8_t*)iv, iv_len, y0);
	}

#if defined(DEBUG)
	printf("Y%d:             ", countY);
	printf_output(y0, BLOCK_CIPHER_BLOCK_SIZE);
#endif

	/* compute ency0 = ENC(K, y0) */
	(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, ency0);

#if defined(DEBUG)
	printf("E(K, Y%d):       ", countY++);
	printf_output(ency0, BLOCK_CIPHER_BLOCK_SIZE);
#endif

	/* encyrption */
	uint8_t * output_temp = output; // store the start pointer of cipher text
	for ( i = 0; i < length/BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
		incr(y0);

#if defined(DEBUG)
		printf("Y%d:             ", countY);
		printf_output(y0, BLOCK_CIPHER_BLOCK_SIZE);
#endif

		(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, output);

#if defined(DEBUG)
		printf("E(K, Y%d):       ", countY++);
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
		printf("Y%d:             ", countY);
		printf_output(y0, BLOCK_CIPHER_BLOCK_SIZE);
#endif
		// the last block size man be smaller than BLOCK_SIZE, can NOT be written directly.
//		(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, output);
		(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, y0);
#if defined(DEBUG)
		printf("E(K, Y%d):       ", countY++);
		printf_output(y0, BLOCK_CIPHER_BLOCK_SIZE);
#endif
		for ( i = 0; i < length%BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
			*(output+i) = *(input+i) ^ *(y0+i);
		}
	}

#if defined(DEBUG)
	printf("CIPHER:         ");
	printf_output(output_temp, length);
#endif

	/* compute tag, y0 is useless now */
	ghash(temp_ctx->T, (const uint8_t *)add, add_len, (const uint8_t*)output_temp, length, y0);

#if defined(DEBUG)
	printf("GHASH(H, A, C): ");
	printf_output(y0, BLOCK_CIPHER_BLOCK_SIZE);
#endif

	for ( i = 0; i < tag_len; i++ ) {
		tag[i] = y0[i] ^ ency0[i];
	}
#if defined(DEBUG)
	printf("TAG:            ");
	printf_output(tag, tag_len);
#endif

	return BLOCK_CIPHER_SUC;
}


/*
 * authenticated decryption
 */
int gcm_auth_decrypt( void *ctx,
              const unsigned char *iv,
              size_t iv_len,
              const unsigned char *add,
              size_t add_len,
              const unsigned char *tag,
              size_t tag_len,
              const unsigned char *input,
              size_t length,
              unsigned char *output ) {
	gcm_context *temp_ctx = (gcm_context*)ctx;
	if ( !temp_ctx || !(temp_ctx->rk) ) { return BLOCK_CIPHER_FAIL; }
	if ( tag_len <= 0 || tag_len > BLOCK_CIPHER_BLOCK_SIZE ) { return BLOCK_CIPHER_FAIL; }

	uint8_t y0[BLOCK_CIPHER_BLOCK_SIZE] = {0}; // store the counter
	uint8_t ency0[BLOCK_CIPHER_BLOCK_SIZE]; // the cihper text of first counter
	uint8_t temp[BLOCK_CIPHER_BLOCK_SIZE] = {0};

#if defined(DEBUG)
	printf("\n----AUTH-DECRYPTION----\n");
	countY = 0;
#endif
	/* compute tag, y0 is useless now */
	ghash(temp_ctx->T, (const uint8_t *)add, add_len, (const uint8_t*)input, length, temp);
#if defined(DEBUG)
	printf("GHASH(H, A, C): ");
	printf_output(temp, BLOCK_CIPHER_BLOCK_SIZE);
#endif

	/* compute y0 (initilization vector) */
	if (DEFAULT_IV_LEN == iv_len) {
		*(uint32_t*)y0 = *(uint32_t*)iv;
		*((uint32_t*)y0+1) = *((uint32_t*)iv+1);
		*((uint32_t*)y0+2) = *((uint32_t*)iv+2);
		y0[15] = 1;
	} else {
		ghash(temp_ctx->T, NULL, 0, (const uint8_t*)iv, iv_len, y0);
	}

	/* compute ency0 = ENC(K, y0) */
	(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, ency0);

	/* authentication */
	int i = 0;
	for ( i = 0; i < tag_len; i++ ) {
		if ( tag[i] != (ency0[i]^temp[i]) ) { break; }
	}
	if ( i != tag_len ) {
		return BLOCK_CIPHER_FAIL;
	}

	/* decyrption */
	uint8_t * output_temp = output;
	for ( i = 0; i < length/BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
		incr(y0);
		(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, output);
		*(uint64_t*)output ^= *(uint64_t*)input;
		*((uint64_t*)output+1) ^= *((uint64_t*)input+1);
		output += BLOCK_CIPHER_BLOCK_SIZE;
	 	input += BLOCK_CIPHER_BLOCK_SIZE;
	}
	// the remaining plain text
	if ( length % BLOCK_CIPHER_BLOCK_SIZE ) {
		incr(y0);
		(temp_ctx->block_encrypt)((const uint8_t *)(temp_ctx->rk), (const uint8_t *)y0, y0);
		for ( i = 0; i < length%BLOCK_CIPHER_BLOCK_SIZE; i++ ) {
			*(output+i) = *(input+i) ^ *(y0+i);
		}
	}

#if defined(DEBUG)
	printf("PLAIN:          ");
	printf_output(output_temp, length);
#endif

	return BLOCK_CIPHER_SUC;

}
