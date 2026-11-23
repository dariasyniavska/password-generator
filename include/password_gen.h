#ifndef PASSWORD_GEN_H
#define PASSWORD_GEN_H

#include "mt19937.h"

#define MIN_PASSWORD_LEN 4
#define MAX_PASSWORD_LEN 128
#define MAX_SPECIAL      64      
#define DEFAULT_LENGTH   16
#define DEFAULT_SPECIAL  "!@#$%^&*()+-_="

extern const char LOWER_LETTERS[];
extern const char UPPER_LETTERS[];
extern const char DIGITS[];

typedef struct {
    int  length;                              

    int  allow_lower;                        
    int  allow_upper;                       
    int  allow_digit;                        
    char allowed_special[MAX_SPECIAL + 1];    

    int  mandatory_lower;                    
    int  mandatory_upper;                     
    int  mandatory_digit;                     
    char mandatory_special[MAX_SPECIAL + 1];  
} PasswordSettings;

typedef enum {
    GEN_OK = 0,
    GEN_ERR_LENGTH,
    GEN_ERR_EMPTY_ALPHABET,
    GEN_ERR_TOO_MANY_MANDATORY,
    GEN_ERR_BAD_SPECIAL
} GenStatus;

void settings_set_default(PasswordSettings *s);

GenStatus normalize_settings(PasswordSettings *s);

int build_alphabet(const PasswordSettings *s, char *alphabet);

GenStatus generate_password(MtState *mt, const PasswordSettings *settings, char *out);

const char *gen_status_text(GenStatus st);

#endif
