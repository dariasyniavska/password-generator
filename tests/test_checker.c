#include <string.h>
#include "test_util.h"
#include "password_check.h"

int main(void)
{
    PasswordSettings s;
    MtState mt;
    char pw[MAX_PASSWORD_LEN + 1];

    settings_set_default(&s);
    s.length = 10;
    strcpy(s.mandatory_special, "@");

    CHECK(check_password("aB3@xxxxxx", &s) == CHECK_OK);

    CHECK(check_password("aB3@xxx", &s)       == CHECK_BAD_LENGTH);
    CHECK(check_password("aB3@xxxxxxx", &s)   == CHECK_BAD_LENGTH);
    CHECK(check_password("aB3@xxxx~x", &s)    == CHECK_BAD_CHAR);  
    CHECK(check_password("aB3@xxxx\"x", &s)   == CHECK_BAD_CHAR);  
    CHECK(check_password("AB3@XXXXXX", &s)    == CHECK_MISSING_LOWER);
    CHECK(check_password("ab3@xxxxxx", &s)    == CHECK_MISSING_UPPER);
    CHECK(check_password("aBc@xxxxxx", &s)    == CHECK_MISSING_DIGIT);
    CHECK(check_password("aB3!xxxxxx", &s)    == CHECK_MISSING_SPECIAL);

    PasswordSettings bad = s;
    bad.length = 0;
    CHECK(check_password("aB3@xxxxxx", &bad) == CHECK_BAD_SETTINGS);

    mt_seed(&mt, 2024u);
    settings_set_default(&s);
    strcpy(s.mandatory_special, "@%");
    int all_pass = 1;
    for (int i = 0; i < 5000; i++) {
        s.length = 4 + (i % 60);
        if (s.length < 5) s.length = 5;
        generate_password(&mt, &s, pw);
        if (check_password(pw, &s) != CHECK_OK) all_pass = 0;
    }
    CHECK(all_pass);

    settings_set_default(&s);                  
    double bits = estimate_entropy_bits(&s);
    CHECK(bits > 99.0 && bits < 101.0);
    CHECK(strength_level(bits) == 5);

    s.length = 4;
    CHECK(strength_level(estimate_entropy_bits(&s)) == 1);  
    s.length = 0;
    CHECK(estimate_entropy_bits(&s) == 0.0);

    CHECK(strength_level(10.0) == 1);
    CHECK(strength_level(30.0) == 2);
    CHECK(strength_level(50.0) == 3);
    CHECK(strength_level(70.0) == 4);
    CHECK(strength_level(90.0) == 5);

    return test_summary("test_checker");
}
