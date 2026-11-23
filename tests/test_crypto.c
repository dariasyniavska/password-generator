#include <string.h>
#include "test_util.h"
#include "crypto.h"

int main(void)
{
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;

    uint8_t nonce1[12] = {0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0};
    uint8_t zeros[64] = {0}, stream[64];
    chacha20_xor(key, nonce1, 1, zeros, stream, 64);
    CHECK(stream[0] == 0x10 && stream[1] == 0xf1 && stream[2] == 0xe7 && stream[3] == 0xe4);

    uint8_t nonce2[12] = {0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0};
    const char *plain = "Ladies and Gentlemen of the class of '99: If I could offer you "
                        "only one tip for the future, sunscreen would be it.";
    size_t plen = strlen(plain);
    uint8_t enc[200];
    chacha20_xor(key, nonce2, 1, (const uint8_t *)plain, enc, plen);
    CHECK(plen == 114);
    CHECK(enc[0] == 0x6e && enc[1] == 0x2e && enc[2] == 0x35 && enc[3] == 0x9a);
    uint8_t dec[200];
    chacha20_xor(key, nonce2, 1, enc, dec, plen);
    CHECK(memcmp(dec, plain, plen) == 0);

    uint8_t raw[4] = {0x00, 0xab, 0xCD, 0xff};
    char hex[16];
    bytes_to_hex(raw, 4, hex);
    CHECK(strcmp(hex, "00abcdff") == 0);
    uint8_t back[4];
    size_t n = 0;
    CHECK(hex_to_bytes("00ABcdFF", back, 4, &n) == 1 && n == 4 && memcmp(back, raw, 4) == 0);
    CHECK(hex_to_bytes("abc", back, 4, &n) == 0);        
    CHECK(hex_to_bytes("zz", back, 4, &n) == 0);         
    CHECK(hex_to_bytes("0011223344", back, 4, &n) == 0); 

    char key_hex[KEY_HEX_SIZE], cipher_hex[CIPHER_HEX_SIZE], out[MAX_PASSWORD_LEN + 1];
    const char *password = "Q7!mP2#vX9@rL4$s";
    CHECK(encrypt_password(password, key_hex, cipher_hex) == CRYPTO_OK);
    CHECK(strlen(key_hex) == 64);
    CHECK(strlen(cipher_hex) == 24 + 2 * strlen(password));
    CHECK(strstr(cipher_hex, "Q7") == NULL);
    CHECK(decrypt_password(key_hex, cipher_hex, out) == CRYPTO_OK);
    CHECK(strcmp(out, password) == 0);

    char upper[CIPHER_HEX_SIZE];
    strcpy(upper, cipher_hex);
    for (int i = 0; upper[i]; i++) if (upper[i] >= 'a' && upper[i] <= 'f') upper[i] -= 32;
    CHECK(decrypt_password(key_hex, upper, out) == CRYPTO_OK && strcmp(out, password) == 0);

    char key2[KEY_HEX_SIZE], cipher2[CIPHER_HEX_SIZE];
    CHECK(encrypt_password(password, key2, cipher2) == CRYPTO_OK);
    CHECK(strcmp(key_hex, key2) != 0);
    CHECK(strcmp(cipher_hex, cipher2) != 0);

    CryptoStatus st = decrypt_password(key2, cipher_hex, out);
    CHECK(st != CRYPTO_OK || strcmp(out, password) != 0);
    CHECK(st == CRYPTO_ERR_WRONG_KEY);

    CHECK(decrypt_password("1234", cipher_hex, out) == CRYPTO_ERR_BAD_KEY);
    CHECK(decrypt_password(key_hex, "xyz", out) == CRYPTO_ERR_BAD_DATA);
    CHECK(decrypt_password(key_hex, "00112233445566778899aabb", out) == CRYPTO_ERR_BAD_DATA); /* лише nonce */
    CHECK(encrypt_password("", key_hex, cipher_hex) == CRYPTO_ERR_BAD_PASSWORD);

    char longpw[MAX_PASSWORD_LEN + 1];
    memset(longpw, 'A', MAX_PASSWORD_LEN);
    longpw[MAX_PASSWORD_LEN] = '\0';
    CHECK(encrypt_password(longpw, key_hex, cipher_hex) == CRYPTO_OK);
    CHECK(decrypt_password(key_hex, cipher_hex, out) == CRYPTO_OK && strcmp(out, longpw) == 0);

    return test_summary("test_crypto");
}
