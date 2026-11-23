#include "crypto.h"

#include <string.h>
#include "entropy.h"

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *a += *b; *d ^= *a; *d = ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL32(*d, 8);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 7);
}

static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void chacha20_block(const uint8_t key[32], uint32_t counter,
                           const uint8_t nonce[12], uint8_t out[64])
{
    uint32_t state[16];
    uint32_t x[16];

    state[0] = 0x61707865u;   
    state[1] = 0x3320646eu;
    state[2] = 0x79622d32u;
    state[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) {
        state[4 + i] = load32_le(key + 4 * i);
    }
    state[12] = counter;
    for (int i = 0; i < 3; i++) {
        state[13 + i] = load32_le(nonce + 4 * i);
    }

    memcpy(x, state, sizeof(state));
    for (int round = 0; round < 10; round++) {          
        quarter_round(&x[0], &x[4], &x[8],  &x[12]);
        quarter_round(&x[1], &x[5], &x[9],  &x[13]);
        quarter_round(&x[2], &x[6], &x[10], &x[14]);
        quarter_round(&x[3], &x[7], &x[11], &x[15]);

        quarter_round(&x[0], &x[5], &x[10], &x[15]);
        quarter_round(&x[1], &x[6], &x[11], &x[12]);
        quarter_round(&x[2], &x[7], &x[8],  &x[13]);
        quarter_round(&x[3], &x[4], &x[9],  &x[14]);
    }

    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + state[i];
        out[4 * i]     = (uint8_t)(v);
        out[4 * i + 1] = (uint8_t)(v >> 8);
        out[4 * i + 2] = (uint8_t)(v >> 16);
        out[4 * i + 3] = (uint8_t)(v >> 24);
    }
}

void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                  const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t block[64];

    for (size_t pos = 0; pos < len; pos += 64) {
        chacha20_block(key, counter, nonce, block);
        counter++;

        size_t chunk = (len - pos < 64) ? (len - pos) : 64;
        for (size_t i = 0; i < chunk; i++) {
            out[pos + i] = in[pos + i] ^ block[i];
        }
    }
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void bytes_to_hex(const uint8_t *data, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = digits[data[i] >> 4];
        out[2 * i + 1] = digits[data[i] & 15];
    }
    out[2 * len] = '\0';
}

int hex_to_bytes(const char *hex, uint8_t *out, size_t max_len, size_t *out_len)
{
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > max_len) {
        return 0;
    }
    for (size_t i = 0; i < len / 2; i++) {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (uint8_t)(hi * 16 + lo);
    }
    *out_len = len / 2;
    return 1;
}


#define NONCE_SIZE 12
#define KEY_SIZE   32

CryptoStatus encrypt_password(const char *password, char *key_hex, char *cipher_hex)
{
    size_t len = strlen(password);
    uint8_t random_part[KEY_SIZE + NONCE_SIZE];
    uint8_t data[MAX_PASSWORD_LEN];

    key_hex[0] = '\0';
    cipher_hex[0] = '\0';

    if (len == 0 || len > MAX_PASSWORD_LEN) {
        return CRYPTO_ERR_BAD_PASSWORD;
    }
    if (!os_random_bytes(random_part, sizeof(random_part))) {
        return CRYPTO_ERR_RANDOM;
    }

    const uint8_t *key = random_part;                
    const uint8_t *nonce = random_part + KEY_SIZE;   

    chacha20_xor(key, nonce, 1, (const uint8_t *)password, data, len);

    bytes_to_hex(key, KEY_SIZE, key_hex);
    bytes_to_hex(nonce, NONCE_SIZE, cipher_hex);             
    bytes_to_hex(data, len, cipher_hex + 2 * NONCE_SIZE);    
    return CRYPTO_OK;
}

CryptoStatus decrypt_password(const char *key_hex, const char *cipher_hex, char *password_out)
{
    uint8_t key[KEY_SIZE];
    uint8_t buf[NONCE_SIZE + MAX_PASSWORD_LEN];
    size_t key_len = 0;
    size_t buf_len = 0;

    password_out[0] = '\0';

    if (!hex_to_bytes(key_hex, key, sizeof(key), &key_len) || key_len != KEY_SIZE) {
        return CRYPTO_ERR_BAD_KEY;
    }
    if (!hex_to_bytes(cipher_hex, buf, sizeof(buf), &buf_len) || buf_len <= NONCE_SIZE) {
        return CRYPTO_ERR_BAD_DATA;
    }

    size_t n = buf_len - NONCE_SIZE;
    chacha20_xor(key, buf, 1, buf + NONCE_SIZE, (uint8_t *)password_out, n);
    password_out[n] = '\0';
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)password_out[i];
        if (c < 33 || c > 126) {
            password_out[0] = '\0';
            return CRYPTO_ERR_WRONG_KEY;
        }
    }
    return CRYPTO_OK;
}

const char *crypto_status_text(CryptoStatus st)
{
    switch (st) {
        case CRYPTO_OK:           return "Готово";
        case CRYPTO_ERR_RANDOM:   return "Операційна система не видала випадкових байтів для ключа";
        case CRYPTO_ERR_BAD_PASSWORD: return "Немає що шифрувати: пароль порожній або задовгий";
        case CRYPTO_ERR_BAD_KEY:  return "Ключ має складатися рівно з 64 hex-символів (0-9, a-f)";
        case CRYPTO_ERR_BAD_DATA: return "Шифротекст має неправильний вигляд (потрібен hex-рядок)";
        case CRYPTO_ERR_WRONG_KEY:return "Ключ не підходить до цього шифротексту";
    }
    return "Невідома помилка";
}
