#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include "password_gen.h"

#define KEY_HEX_SIZE    65                         
#define CIPHER_HEX_SIZE (24 + 2 * MAX_PASSWORD_LEN + 1)  

typedef enum {
    CRYPTO_OK = 0,
    CRYPTO_ERR_RANDOM,        
    CRYPTO_ERR_BAD_PASSWORD,  
    CRYPTO_ERR_BAD_KEY,       
    CRYPTO_ERR_BAD_DATA,     
    CRYPTO_ERR_WRONG_KEY      
} CryptoStatus;

void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                  const uint8_t *in, uint8_t *out, size_t len);

void bytes_to_hex(const uint8_t *data, size_t len, char *out);               
int  hex_to_bytes(const char *hex, uint8_t *out, size_t max_len, size_t *out_len);

CryptoStatus encrypt_password(const char *password, char *key_hex, char *cipher_hex);

CryptoStatus decrypt_password(const char *key_hex, const char *cipher_hex, char *password_out);

const char *crypto_status_text(CryptoStatus st);

#endif
