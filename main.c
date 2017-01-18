
#include <stdio.h>
#include <stdlib.h>

#include "aes.h"
#include "gcm.h"

#define TEST_CASE (6)

operation_result encryption (const unsigned char *key,
	const unsigned char *iv,
    size_t iv_len,
    const unsigned char *add,
    size_t add_len,
    const unsigned char *input,
    size_t length,
    unsigned char *output,
    unsigned char *tag,
    size_t tag_len) {

	void * context = gcm_init();
	if ( !context ) { 
		printf("malloc failed.\n");
		return OPERATION_FAIL;
	}
	
	operation_result flag = gcm_setkey(context, key, 128 );
	if ( OPERATION_FAIL == flag ) { return OPERATION_FAIL; }

	gcm_crypt_and_tag(context,
		iv, iv_len,
		add, add_len,
		input, length,
		output,
		tag, tag_len);

	gcm_free( context);

	return OPERATION_SUC;

}

operation_result decryption (const unsigned char *key,
	const unsigned char *iv,
    size_t iv_len,
    const unsigned char *add,
    size_t add_len,
    const unsigned char *tag,
    size_t tag_len,
    const unsigned char *input,
    size_t length,
    unsigned char *output ) {

	void * context = gcm_init();
	if ( !context ) { 
		printf("malloc failed.\n");
		return 0;
	}
	
	operation_result flag = gcm_setkey(context, key, 128);
	if ( OPERATION_FAIL == flag ) { return OPERATION_FAIL; }

	gcm_auth_decrypt( context,
		iv, iv_len,
		add, add_len,
		tag, tag_len,
		input, length,
		output);

	gcm_free( context);

	return OPERATION_SUC;

}

int main(int argc, char *argv[]) {

#if defined(TEST_CASE) && (TEST_CASE==1)
	uint8_t key[AES_BLOCK_SIZE] = {0};
	uint8_t *input = NULL;
	uint8_t *output = NULL;
	size_t length = 0;
	uint8_t *add = NULL;
	size_t add_len = 0;
	uint8_t iv[GCM_DEFAULT_IV_LEN] = {0};
	size_t iv_len = GCM_DEFAULT_IV_LEN;

#elif defined(TEST_CASE) && (TEST_CASE==2)
	uint8_t key[AES_BLOCK_SIZE] = {0};
	uint8_t input[AES_BLOCK_SIZE] = {0};
	uint8_t output[AES_BLOCK_SIZE];
	size_t length = AES_BLOCK_SIZE;
	uint8_t *add = NULL;
	size_t add_len = 0;
	uint8_t iv[GCM_DEFAULT_IV_LEN] = {0};
	size_t iv_len = GCM_DEFAULT_IV_LEN;

#elif defined(TEST_CASE) && (TEST_CASE==3)
	uint8_t key[AES_BLOCK_SIZE] = {
		0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
	size_t length = AES_BLOCK_SIZE*4;
	uint8_t input[AES_BLOCK_SIZE*4] = {
		0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
		0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
		0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
		0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55};
	uint8_t output[AES_BLOCK_SIZE*4];
	size_t add_len = 0;
	uint8_t *add = NULL;
	size_t iv_len = GCM_DEFAULT_IV_LEN;
	uint8_t iv[GCM_DEFAULT_IV_LEN] = {
		0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};

#elif defined(TEST_CASE) && (TEST_CASE==4)
	uint8_t key[AES_BLOCK_SIZE] = {
		0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
	size_t length = AES_BLOCK_SIZE*3+GCM_DEFAULT_IV_LEN;
	uint8_t input[AES_BLOCK_SIZE*3+GCM_DEFAULT_IV_LEN] = {
		0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
		0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
		0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
		0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};
	uint8_t output[AES_BLOCK_SIZE*3+GCM_DEFAULT_IV_LEN];
	size_t add_len = AES_BLOCK_SIZE+4;
	uint8_t add[AES_BLOCK_SIZE+4] = {
		0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
		0xab, 0xad, 0xda, 0xd2};
	size_t iv_len = GCM_DEFAULT_IV_LEN;
	uint8_t iv[GCM_DEFAULT_IV_LEN] = {
		0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};

#elif defined(TEST_CASE) && (TEST_CASE==5)
	uint8_t key[AES_BLOCK_SIZE] = {
		0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
	size_t length = AES_BLOCK_SIZE*3+GCM_DEFAULT_IV_LEN;
	uint8_t input[AES_BLOCK_SIZE*3+GCM_DEFAULT_IV_LEN] = {
		0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
		0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
		0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
		0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};
	uint8_t output[AES_BLOCK_SIZE*3+GCM_DEFAULT_IV_LEN];
	size_t add_len = AES_BLOCK_SIZE+4;
	uint8_t add[AES_BLOCK_SIZE+4] = {
		0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
		0xab, 0xad, 0xda, 0xd2};
	size_t iv_len = GCM_DEFAULT_IV_LEN-4;
	uint8_t iv[GCM_DEFAULT_IV_LEN-4] = {
		0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad};

#elif defined(TEST_CASE) && (TEST_CASE==6)
	uint8_t key[AES_BLOCK_SIZE] = {
		0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
	size_t length = AES_BLOCK_SIZE*3+GCM_DEFAULT_IV_LEN;
	uint8_t input[AES_BLOCK_SIZE*3+GCM_DEFAULT_IV_LEN] = {
		0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
		0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
		0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
		0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};
	uint8_t output[AES_BLOCK_SIZE*3+GCM_DEFAULT_IV_LEN];
	size_t add_len = AES_BLOCK_SIZE+4;
	uint8_t add[AES_BLOCK_SIZE+4] = {
		0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
		0xab, 0xad, 0xda, 0xd2};
	size_t iv_len = 4*AES_BLOCK_SIZE-4;
	uint8_t iv[4*AES_BLOCK_SIZE-4] = {
		0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5, 0x55, 0x90, 0x9c, 0x5a, 0xff, 0x52, 0x69, 0xaa,
		0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d, 0xa1, 0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28,
		0xc3, 0xc0, 0xc9, 0x51, 0x56, 0x80, 0x95, 0x39, 0xfc, 0xf0, 0xe2, 0x42, 0x9a, 0x6b, 0x52, 0x54,
		0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57, 0xa6, 0x37, 0xb3, 0x9b};
#endif
	
	uint8_t tag[16] = {0};
	size_t tag_len = 16;

	encryption(key,
		iv, iv_len,
		add, add_len,
		input, length,
		output,
		tag, tag_len);

	decryption(key,
		iv, iv_len,
		add, add_len,
		tag, tag_len,
		output, length,
		input);	

	return 0;

}