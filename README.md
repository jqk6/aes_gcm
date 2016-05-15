### AES-128 in GCM

Only AES-128 is used. The code is tested with GCC under Ubuntu 14.04.<br>

The interfaces of AES are as follows. You can use your own implementation, <a href="https://github.com/openluopworld/aes_128">here</a> is an example (just copy the <i>aes.h</i> and <i>aes.c</i> files).<b>
```C
/**
 * Key schedule for AES-128
 */
void aes_key_schedule_128(const uint8_t *key, uint8_t *roundkeys);
/**
 * Encryption. Only one block is encrypted.
 */
void aes_encrypt_128(const uint8_t *roundkeys, const uint8_t *plain, uint8_t *cipher);
/**
 * Decryption. Only one block is decrypted.
 */
void aes_decrypt_128(const uint8_t *roundkeys, const uint8_t *cipher, uint8_t *plain);
```

The design of <a href="http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf">The Galois/Counter Mode of Operation (GCM)</a><br>

The interfaces are as follows.<br>
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

According to <a href="http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf">The Galois/Counter Mode of Operation (GCM)</a>, 6 test cases are given is the code (<i>main.c</i>). You can just change the value of <b><i>TEST_CASE</i></b>(from 1 to 6) for different test vectors.<br>
