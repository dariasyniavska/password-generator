#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <stdio.h>

static int g_tests_run = 0;
static int g_tests_failed = 0;

#define CHECK(cond) do { \
    g_tests_run++; \
    if (!(cond)) { \
        g_tests_failed++; \
        printf("  ПОМИЛКА: %s (рядок %d)\n", #cond, __LINE__); \
    } \
} while (0)

static int test_summary(const char *name)
{
    printf("%s: перевірок %d, помилок %d\n", name, g_tests_run, g_tests_failed);
    return g_tests_failed == 0 ? 0 : 1;
}

#endif
