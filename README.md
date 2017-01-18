# AES-128 in GCM
THIS CODE IS JUST FOR UNDERSTANDING AND STUDY.

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

### How to Use
* Encryption
```C
void * context = gcm_init();
if ( !context ) { return OPERATION_FAIL; }

operation_result flag = gcm_setkey(context, key, 128 );

if ( OPERATION_FAIL != flag ) {
	gcm_crypt_and_tag(context,
		iv, iv_len,
		add, add_len,
		input, length,
		output,
		tag, tag_len);
}

gcm_free( context);
```
* Decryption
```C
void * context = gcm_init();
if ( !context ) { return OPERATION_FAIL; }

operation_result flag = gcm_setkey(context, key, 128 );

if ( OPERATION_FAIL != flag ) {
	gcm_auth_decrypt( context,
		iv, iv_len,
		add, add_len,
		tag, tag_len,
		input, length,
		output);
}

gcm_free( context);
```

### How to test
According to [The Galois/Counter Mode of Operation (GCM)], 6 test cases are given is *main.c*. You can just change the value of *TEST_CASE(from 1 to 6)* for different test vectors.

[The Galois/Counter Mode of Operation (GCM)]:<http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf>