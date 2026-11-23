#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "entropy.h"
#include "password_gen.h"
#include "password_check.h"
#include "crypto.h"

static int ask_yes_no(const char *question, int default_value)
{
    char line[64];
    printf("%s (y/n) [%c]: ", question, default_value ? 'y' : 'n');
    if (fgets(line, sizeof(line), stdin) == NULL) {
        return default_value;
    }
    if (line[0] == 'y' || line[0] == 'Y') {
        return 1;
    }
    if (line[0] == 'n' || line[0] == 'N') {
        return 0;
    }
    return default_value;
}

static void ask_string(const char *question, char *value, int max_len)
{
    char line[256];
    printf("%s [%s]: ", question, value);
    if (fgets(line, sizeof(line), stdin) == NULL) {
        return;
    }
    line[strcspn(line, "\r\n")] = '\0';
    if (line[0] != '\0' && (int)strlen(line) <= max_len) {
        strcpy(value, line);
    }
}

static void ask_settings(PasswordSettings *s)
{
    char line[64];

    printf("Довжина пароля [%d]: ", s->length);
    if (fgets(line, sizeof(line), stdin) != NULL && atoi(line) != 0) {
        s->length = atoi(line);
    }

    s->allow_lower = ask_yes_no("Малі літери дозволені", s->allow_lower);
    s->allow_upper = ask_yes_no("Великі літери дозволені", s->allow_upper);
    s->allow_digit = ask_yes_no("Цифри дозволені", s->allow_digit);
    ask_string("Дозволені спецсимволи", s->allowed_special, MAX_SPECIAL);

    s->mandatory_lower = ask_yes_no("Мала літера обов’язкова", s->mandatory_lower);
    s->mandatory_upper = ask_yes_no("Велика літера обов’язкова", s->mandatory_upper);
    s->mandatory_digit = ask_yes_no("Цифра обов’язкова", s->mandatory_digit);
    ask_string("Обов’язкові спецсимволи", s->mandatory_special, MAX_SPECIAL);
}

int main(void)
{
    MtState mt;
    PasswordSettings settings;
    char password[MAX_PASSWORD_LEN + 1];

    mt_seed_from_os(&mt);
    settings_set_default(&settings);

    printf("=== Генератор паролів ===\n");
    printf("(Enter - залишити значення в дужках)\n\n");
    ask_settings(&settings);

    GenStatus st = generate_password(&mt, &settings, password);
    if (st != GEN_OK) {
        printf("\nПомилка: %s\n", gen_status_text(st));
        return 1;
    }

    double bits = estimate_entropy_bits(&settings);
    int level = strength_level(bits);

    printf("\nЗгенерований пароль: %s\n", password);
    printf("Стійкість: %s (≈ %.0f біт)\n", strength_text(level), bits);
    printf("Перевірка: %s\n", check_status_text(check_password(password, &settings)));

    if (ask_yes_no("\nЗашифрувати пароль?", 0)) {
        char key_hex[KEY_HEX_SIZE];
        char cipher_hex[CIPHER_HEX_SIZE];
        char decrypted[MAX_PASSWORD_LEN + 1];

        CryptoStatus cs = encrypt_password(password, key_hex, cipher_hex);
        if (cs != CRYPTO_OK) {
            printf("Помилка шифрування: %s\n", crypto_status_text(cs));
            return 1;
        }
        printf("Ключ (збережіть окремо!): %s\n", key_hex);
        printf("Шифротекст:               %s\n", cipher_hex);

        cs = decrypt_password(key_hex, cipher_hex, decrypted);
        printf("Перевірка розшифрування: %s\n",
               (cs == CRYPTO_OK && strcmp(decrypted, password) == 0) ? "пароль збігається" : "ПОМИЛКА");
    }
    return 0;
}
