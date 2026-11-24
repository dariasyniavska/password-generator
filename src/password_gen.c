#include "password_gen.h"

#include <ctype.h>
#include <string.h>

const char LOWER_LETTERS[] = "abcdefghijklmnopqrstuvwxyz";
const char UPPER_LETTERS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char DIGITS[]        = "0123456789";

static int is_special_char(char c)
{
    unsigned char u = (unsigned char)c;
    return u >= 33 && u <= 126 && !isalnum(u);
}

static int copy_unique_specials(const char *src, char *dst)
{
    int n = 0;
    dst[0] = '\0';
    for (int i = 0; src[i] != '\0'; i++) {
        if (!is_special_char(src[i])) {
            return 0;
        }
        if (strchr(dst, src[i]) == NULL) {
            if (n >= MAX_SPECIAL) {
                return 0;
            }
            dst[n] = src[i];
            n++;
            dst[n] = '\0';
        }
    }
    return 1;
}

static int random_index(MtState *mt, int n)
{
    int i = (int)(mt_next_double(mt) * n);
    if (i >= n) {
        i = n - 1;
    }
    return i;
}

void settings_set_default(PasswordSettings *s)
{
    memset(s, 0, sizeof(*s));
    s->length = DEFAULT_LENGTH;

    s->allow_lower = 1;
    s->allow_upper = 1;
    s->allow_digit = 1;
    strcpy(s->allowed_special, DEFAULT_SPECIAL);

    s->mandatory_lower = 1;
    s->mandatory_upper = 1;
    s->mandatory_digit = 1;
    s->mandatory_special[0] = '\0';
}

GenStatus normalize_settings(PasswordSettings *s)
{
    if (s->length < MIN_PASSWORD_LEN || s->length > MAX_PASSWORD_LEN) {
        return GEN_ERR_LENGTH;
    }

    char clean_allowed[MAX_SPECIAL + 1] = "";
    char clean_mandatory[MAX_SPECIAL + 1] = "";
    if (!copy_unique_specials(s->allowed_special, clean_allowed)) {
        return GEN_ERR_BAD_SPECIAL;
    }
    if (!copy_unique_specials(s->mandatory_special, clean_mandatory)) {
        return GEN_ERR_BAD_SPECIAL;
    }

    if (s->mandatory_lower) s->allow_lower = 1;
    if (s->mandatory_upper) s->allow_upper = 1;
    if (s->mandatory_digit) s->allow_digit = 1;

    for (int i = 0; clean_mandatory[i] != '\0'; i++) {
        if (strchr(clean_allowed, clean_mandatory[i]) == NULL) {
            return GEN_ERR_MANDATORY_NOT_ALLOWED;
        }
    }

    strcpy(s->allowed_special, clean_allowed);
    strcpy(s->mandatory_special, clean_mandatory);

    if (!s->allow_lower && !s->allow_upper && !s->allow_digit
        && s->allowed_special[0] == '\0') {
        return GEN_ERR_EMPTY_ALPHABET;
    }

    int required = s->mandatory_lower + s->mandatory_upper + s->mandatory_digit
                 + (int)strlen(s->mandatory_special);
    if (required > s->length) {
        return GEN_ERR_TOO_MANY_MANDATORY;
    }

    return GEN_OK;
}

int build_alphabet(const PasswordSettings *s, char *alphabet)
{
    alphabet[0] = '\0';
    if (s->allow_lower) strcat(alphabet, LOWER_LETTERS);
    if (s->allow_upper) strcat(alphabet, UPPER_LETTERS);
    if (s->allow_digit) strcat(alphabet, DIGITS);
    strcat(alphabet, s->allowed_special);
    return (int)strlen(alphabet);
}

static void ensure_mandatory(MtState *mt, const PasswordSettings *s, char *pw)
{
    const char *req[3 + MAX_SPECIAL];
    char single[MAX_SPECIAL][2];
    int  satisfied[3 + MAX_SPECIAL] = {0};
    int  locked[MAX_PASSWORD_LEN] = {0};
    int  n_req = 0;

    if (s->mandatory_lower) req[n_req++] = LOWER_LETTERS;
    if (s->mandatory_upper) req[n_req++] = UPPER_LETTERS;
    if (s->mandatory_digit) req[n_req++] = DIGITS;
    for (int i = 0; s->mandatory_special[i] != '\0'; i++) {
        single[i][0] = s->mandatory_special[i];
        single[i][1] = '\0';
        req[n_req++] = single[i];
    }

    for (int r = 0; r < n_req; r++) {
        for (int p = 0; p < s->length; p++) {
            if (!locked[p] && strchr(req[r], pw[p]) != NULL) {
                locked[p] = 1;
                satisfied[r] = 1;
                break;
            }
        }
    }

    for (int r = 0; r < n_req; r++) {
        if (satisfied[r]) {
            continue;
        }
        int p;
        do {
            p = random_index(mt, s->length);
        } while (locked[p]);

        pw[p] = req[r][random_index(mt, (int)strlen(req[r]))];
        locked[p] = 1;
    }
}

GenStatus generate_password(MtState *mt, const PasswordSettings *settings, char *out)
{
    PasswordSettings s = *settings;
    out[0] = '\0';

    GenStatus st = normalize_settings(&s);
    if (st != GEN_OK) {
        return st;
    }

    char alphabet[128];
    int alphabet_len = build_alphabet(&s, alphabet);

    double mass_random_float[MAX_PASSWORD_LEN];
    for (int i = 0; i < s.length; i++) {
        mass_random_float[i] = mt_next_double(mt);
    }

    for (int i = 0; i < s.length; i++) {
        int index = (int)(mass_random_float[i] * alphabet_len);
        if (index >= alphabet_len) {
            index = alphabet_len - 1;
        }
        out[i] = alphabet[index];
    }
    out[s.length] = '\0';

    ensure_mandatory(mt, &s, out);
    return GEN_OK;
}

const char *gen_status_text(GenStatus st)
{
    switch (st) {
        case GEN_OK:                       return "Все гаразд";
        case GEN_ERR_LENGTH:               return "Довжина пароля має бути від 4 до 128 символів";
        case GEN_ERR_EMPTY_ALPHABET:       return "Не вибрано жодного типу символів";
        case GEN_ERR_TOO_MANY_MANDATORY:   return "Обов’язкових символів більше, ніж довжина пароля";
        case GEN_ERR_BAD_SPECIAL:          return "У полі спецсимволів можуть бути лише знаки (не літери, цифри чи пробіл)";
        case GEN_ERR_MANDATORY_NOT_ALLOWED:return "Обов’язкові спецсимволи мають бути серед дозволених";
    }
    return "Невідома помилка";
}
