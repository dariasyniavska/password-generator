#ifndef PASSWORD_CHECK_H
#define PASSWORD_CHECK_H

#include "password_gen.h"

typedef enum {
    CHECK_OK = 0,
    CHECK_BAD_SETTINGS,
    CHECK_BAD_LENGTH,
    CHECK_BAD_CHAR,
    CHECK_MISSING_LOWER,
    CHECK_MISSING_UPPER,
    CHECK_MISSING_DIGIT,
    CHECK_MISSING_SPECIAL
} CheckStatus;

CheckStatus check_password(const char *password, const PasswordSettings *settings);

const char *check_status_text(CheckStatus st);

double estimate_entropy_bits(const PasswordSettings *settings);

int strength_level(double bits);

const char *strength_text(int level);

#endif
