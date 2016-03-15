
#ifndef AES_H
#define AES_H

#include <stdio.h>
#include <stdint.h>

/*
 * Number of columns (32-bit words) comprising the State. For this 
 * standard, Nb = 4.
 */
#define Nb (4)

/*
 * Number of 32-bit words comprising the Cipher Key. For this 
 * standard, Nk = 4, 6, or 8.
 */
#define Nk (4)

/*
 * Number of rounds, which is a function of  Nk  and  Nb (which is 
 * fixed). For this standard, Nr = 10, 12, or 14.
 */
#define Nr (10)

void aes_key_schedule_128(uint8_t *w, const uint8_t *key);

void aes_encrypt_128(const uint8_t *w, const uint8_t *in, uint8_t *out);

void aes_decrypt_128(const uint8_t *w, const uint8_t *in, uint8_t *out);

#endif
