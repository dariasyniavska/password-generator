#include "password_check.h"

#include <math.h>
#include <string.h>

CheckStatus check_password(const char *password, const PasswordSettings *settings)
{
    PasswordSettings s = *settings;
    if (normalize_settings(&s) != GEN_OK) {
        return CHECK_BAD_SETTINGS;
    }

    int len = (int)strlen(password);
    if (len != s.length) {
        return CHECK_BAD_LENGTH;
    }

    char alphabet[128];
    build_alphabet(&s, alphabet);

    int has_lower = 0, has_upper = 0, has_digit = 0;
    for (int i = 0; i < len; i++) {
        char c = password[i];
        if (strchr(alphabet, c) == NULL) {
            return CHECK_BAD_CHAR;   
        }
        if (strchr(LOWER_LETTERS, c) != NULL) has_lower = 1;
        if (strchr(UPPER_LETTERS, c) != NULL) has_upper = 1;
        if (strchr(DIGITS, c) != NULL)        has_digit = 1;
    }

    if (s.mandatory_lower && !has_lower) return CHECK_MISSING_LOWER;
    if (s.mandatory_upper && !has_upper) return CHECK_MISSING_UPPER;
    if (s.mandatory_digit && !has_digit) return CHECK_MISSING_DIGIT;

    for (int i = 0; s.mandatory_special[i] != '\0'; i++) {
        if (strchr(password, s.mandatory_special[i]) == NULL) {
            return CHECK_MISSING_SPECIAL;
        }
    }

    return CHECK_OK;
}

const char *check_status_text(CheckStatus st)
{
    switch (st) {
        case CHECK_OK:              return "Пароль відповідає налаштуванням";
        case CHECK_BAD_SETTINGS:    return "Налаштування некоректні, перевірити неможливо";
        case CHECK_BAD_LENGTH:      return "Довжина пароля не збігається з налаштуваннями";
        case CHECK_BAD_CHAR:        return "У паролі є символ, який не дозволений налаштуваннями";
        case CHECK_MISSING_LOWER:   return "У паролі немає обов’язкової малої літери";
        case CHECK_MISSING_UPPER:   return "У паролі немає обов’язкової великої літери";
        case CHECK_MISSING_DIGIT:   return "У паролі немає обов’язкової цифри";
        case CHECK_MISSING_SPECIAL: return "У паролі немає одного з обов’язкових спецсимволів";
    }
    return "Невідомий результат";
}

double estimate_entropy_bits(const PasswordSettings *settings)
{
    PasswordSettings s = *settings;
    if (normalize_settings(&s) != GEN_OK) {
        return 0.0;
    }
    char alphabet[128];
    int alphabet_len = build_alphabet(&s, alphabet);
    return s.length * log2((double)alphabet_len);
}

int strength_level(double bits)
{
    if (bits < 28.0) return 1;
    if (bits < 36.0) return 2;
    if (bits < 60.0) return 3;
    if (bits < 80.0) return 4;
    return 5;
}

const char *strength_text(int level)
{
    switch (level) {
        case 1:  return "Дуже слабкий";
        case 2:  return "Слабкий";
        case 3:  return "Середній";
        case 4:  return "Добрий";
        case 5:  return "Сильний";
    }
    return "Невідомо";
}
