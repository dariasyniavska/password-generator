#include <string.h>
#include "test_util.h"
#include "password_gen.h"

static int all_chars_in(const char *text, const char *set)
{
    for (int i = 0; text[i] != '\0'; i++) {
        if (strchr(set, text[i]) == NULL) return 0;
    }
    return 1;
}

int main(void)
{
    MtState mt;
    PasswordSettings s;
    char pw[MAX_PASSWORD_LEN + 1];
    char alphabet[128];

    mt_seed(&mt, 12345u);

    settings_set_default(&s);
    CHECK(s.length == 16);
    CHECK(generate_password(&mt, &s, pw) == GEN_OK);
    CHECK(strlen(pw) == 16);
    build_alphabet(&s, alphabet);
    CHECK(strlen(alphabet) == 26 + 26 + 10 + strlen(DEFAULT_SPECIAL));
    CHECK(all_chars_in(pw, alphabet));

    int unique = 1;
    for (int i = 0; alphabet[i] != '\0'; i++) {
        if (strchr(alphabet + i + 1, alphabet[i]) != NULL) unique = 0;
    }
    CHECK(unique);

    settings_set_default(&s);
    s.length = 6;
    strcpy(s.mandatory_special, "@#");
    int always_ok = 1;
    for (int i = 0; i < 20000; i++) {
        generate_password(&mt, &s, pw);
        int has_lower = 0, has_upper = 0, has_digit = 0;
        for (int k = 0; pw[k]; k++) {
            if (strchr(LOWER_LETTERS, pw[k])) has_lower = 1;
            if (strchr(UPPER_LETTERS, pw[k])) has_upper = 1;
            if (strchr(DIGITS, pw[k]))        has_digit = 1;
        }
        if (!has_lower || !has_upper || !has_digit) always_ok = 0;
        if (!strchr(pw, '@') || !strchr(pw, '#')) always_ok = 0;
        if (strlen(pw) != 6) always_ok = 0;
    }
    CHECK(always_ok);

    settings_set_default(&s);
    s.length = 4;
    strcpy(s.mandatory_special, "!");
    CHECK(generate_password(&mt, &s, pw) == GEN_OK);
    CHECK(strchr(pw, '!') != NULL);

    settings_set_default(&s);
    s.allow_lower = 0;
    s.length = 10;
    CHECK(generate_password(&mt, &s, pw) == GEN_OK);
    int has_lower = 0;
    for (int k = 0; pw[k]; k++) if (strchr(LOWER_LETTERS, pw[k])) has_lower = 1;
    CHECK(has_lower);

    settings_set_default(&s);
    s.allowed_special[0] = '\0';
    strcpy(s.mandatory_special, "=");
    CHECK(normalize_settings(&s) == GEN_OK);
    CHECK(strchr(s.allowed_special, '=') != NULL);
    CHECK(generate_password(&mt, &s, pw) == GEN_OK);
    CHECK(strchr(pw, '=') != NULL);

    settings_set_default(&s);
    s.allow_lower = s.allow_upper = 0;
    s.mandatory_lower = s.mandatory_upper = 0;
    s.allowed_special[0] = '\0';
    s.length = 30;
    CHECK(generate_password(&mt, &s, pw) == GEN_OK);
    CHECK(all_chars_in(pw, DIGITS));

    settings_set_default(&s);
    s.length = 0;
    CHECK(generate_password(&mt, &s, pw) == GEN_ERR_LENGTH);
    CHECK(pw[0] == '\0');
    s.length = MAX_PASSWORD_LEN + 1;
    CHECK(generate_password(&mt, &s, pw) == GEN_ERR_LENGTH);

    settings_set_default(&s);
    s.allow_lower = s.allow_upper = s.allow_digit = 0;
    s.mandatory_lower = s.mandatory_upper = s.mandatory_digit = 0;
    s.allowed_special[0] = '\0';
    CHECK(generate_password(&mt, &s, pw) == GEN_ERR_EMPTY_ALPHABET);

    settings_set_default(&s);
    s.length = 4;
    strcpy(s.mandatory_special, "!@#");
    CHECK(generate_password(&mt, &s, pw) == GEN_ERR_TOO_MANY_MANDATORY);

    settings_set_default(&s);
    strcpy(s.allowed_special, "!a");
    CHECK(generate_password(&mt, &s, pw) == GEN_ERR_BAD_SPECIAL);
    settings_set_default(&s);
    strcpy(s.allowed_special, " ");
    CHECK(generate_password(&mt, &s, pw) == GEN_ERR_BAD_SPECIAL);
    settings_set_default(&s);
    strcpy(s.mandatory_special, "! ");
    CHECK(generate_password(&mt, &s, pw) == GEN_ERR_BAD_SPECIAL);

    settings_set_default(&s);
    s.allow_lower = s.allow_upper = 0;
    s.mandatory_lower = s.mandatory_upper = 0;
    s.allowed_special[0] = '\0';
    s.length = 100;
    int count[10] = {0};
    for (int i = 0; i < 1000; i++) {
        generate_password(&mt, &s, pw);
        for (int k = 0; k < 100; k++) count[pw[k] - '0']++;
    }
    int uniform = 1;
    for (int d = 0; d < 10; d++) {
        if (count[d] < 9500 || count[d] > 10500) uniform = 0;
    }
    CHECK(uniform);

    settings_set_default(&s);
    char pw2[MAX_PASSWORD_LEN + 1];
    generate_password(&mt, &s, pw);
    generate_password(&mt, &s, pw2);
    CHECK(strcmp(pw, pw2) != 0);

    return test_summary("test_generator");
}
