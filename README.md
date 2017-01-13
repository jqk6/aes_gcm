# AES-128 in GCM

### AES-128
Only AES-128 is used. The code is tested with GCC under Ubuntu 14.04. The interfaces of AES are as follows.
```C
/**
 * @purpose:			Key schedule for AES-128
 * @par[in]key:			16 bytes of master keys
 * @par[out]roundkeys:	176 bytes of round keys
 */
void aes_key_schedule_128(const uint8_t *key, uint8_t *roundkeys);

/**
 * @purpose:			Encryption. The length of plain and cipher should be one block (16 bytes).
 *						The plaintext and ciphertext may point to the same memory
 * @par[in]roundkeys:	round keys
 * @par[in]plaintext:	plain text
 * @par[out]ciphertext:	cipher text
 */
void aes_encrypt_128(const uint8_t *roundkeys, const uint8_t *plaintext, uint8_t *ciphertext);

/**
 * @purpose:			Decryption. The length of plain and cipher should be one block (16 bytes).
 *						The ciphertext and plaintext may point to the same memory
 * @par[in]roundkeys:	round keys
 * @par[in]ciphertext:	cipher text
 * @par[out]plaintext:	plain text
 */
void aes_decrypt_128(const uint8_t *roundkeys, const uint8_t *ciphertext, uint8_t *plaintext);
```

### GCM

The interfaces of GCM are as follows.
```C
int mbedtls_gcm_crypt_and_tag( void *ctx,
		const unsigned char *iv,
		size_t iv_len,
		const unsigned char *add,
		size_t add_len,
		const unsigned char *input,
		size_t length,
		unsigned char *output,
		unsigned char *tag,
		size_t tag_len);
int mbedtls_gcm_auth_decrypt( void *ctx,
		const unsigned char *iv,
		size_t iv_len,
		const unsigned char *add,
		size_t add_len,
		const unsigned char *tag,
		size_t tag_len,
		const unsigned char *input,
		size_t length,
		unsigned char *output );
```

According to [The Galois/Counter Mode of Operation (GCM)], 6 test cases are given is *main.c*. You can just change the value of *TEST_CASE(from 1 to 6)* for different test vectors.


[The Galois/Counter Mode of Operation (GCM)]:(http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf)