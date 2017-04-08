# AES-GCM

[![Build Status](https://travis-ci.org/openluopworld/aes_gcm.svg?branch=master)](https://travis-ci.org/openluopworld/aes_gcm)

THIS CODE IS JUST FOR UNDERSTANDING AND STUDY.

The code has been tested with GCC 4.8.4 and Valgrind-3.11.0. The block cipher is AES-128.

## Usage

### Encryption
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

### Decryption
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

## How to test
According to [The Galois/Counter Mode of Operation (GCM)], 6 test cases are given is *main.c*. You can just change the value of *TEST_CASE(from 1 to 6)* for different test vectors.

### Compile
```sh
make
```

## License

> Copyright (c) 2017 LuoPeng
> 
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
> 
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
> 
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

[The Galois/Counter Mode of Operation (GCM)]:<http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf>