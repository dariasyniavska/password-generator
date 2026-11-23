#include "entropy.h"

#include <stdio.h>
#include <time.h>

#ifdef _WIN32
  #include <windows.h>
  #include <bcrypt.h>
  #ifdef _MSC_VER
    #pragma comment(lib, "bcrypt.lib")
  #endif
#endif

#define SEED_WORDS 8   

int os_random_bytes(void *buf, size_t n)
{
#ifdef _WIN32
    NTSTATUS st = BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)n,
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return st >= 0;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        return 0;
    }
    size_t got = fread(buf, 1, n, f);
    fclose(f);
    return got == n;
#endif
}

void mt_seed_from_os(MtState *mt)
{
    uint32_t words[SEED_WORDS];

    if (!os_random_bytes(words, sizeof(words))) {
        uint32_t t = (uint32_t)time(NULL);
        uint32_t c = (uint32_t)clock();
        for (int i = 0; i < SEED_WORDS; i++) {
            words[i] = (t * 2654435761u) ^ (c + (uint32_t)i * 40503u);
            t += 0x9e3779b9u;
        }
    }

    mt_seed_array(mt, words, SEED_WORDS);
}
