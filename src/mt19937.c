#include "mt19937.h"

#define MT_M 397

void mt_seed(MtState *mt, uint32_t seed)
{
    mt->state[0] = seed;
    for (int i = 1; i < MT_N; i++) {
        uint32_t prev = mt->state[i - 1];
        mt->state[i] = 1812433253u * (prev ^ (prev >> 30)) + (uint32_t)i;
    }
    mt->index = MT_N;   
}

void mt_seed_array(MtState *mt, const uint32_t key[], int key_len)
{
    int i = 1;
    int j = 0;
    int k = (MT_N > key_len) ? MT_N : key_len;

    mt_seed(mt, 19650218u);

    for (; k > 0; k--) {
        uint32_t prev = mt->state[i - 1];
        mt->state[i] = (mt->state[i] ^ ((prev ^ (prev >> 30)) * 1664525u))
                       + key[j] + (uint32_t)j;
        i++;
        j++;
        if (i >= MT_N) {
            mt->state[0] = mt->state[MT_N - 1];
            i = 1;
        }
        if (j >= key_len) {
            j = 0;
        }
    }

    for (k = MT_N - 1; k > 0; k--) {
        uint32_t prev = mt->state[i - 1];
        mt->state[i] = (mt->state[i] ^ ((prev ^ (prev >> 30)) * 1566083941u))
                       - (uint32_t)i;
        i++;
        if (i >= MT_N) {
            mt->state[0] = mt->state[MT_N - 1];
            i = 1;
        }
    }

    mt->state[0] = 0x80000000u;
    mt->index = MT_N;
}

static void mt_twist(MtState *mt)
{
    for (int i = 0; i < MT_N; i++) {
        uint32_t y = (mt->state[i] & 0x80000000u)
                   | (mt->state[(i + 1) % MT_N] & 0x7fffffffu);
        uint32_t next = mt->state[(i + MT_M) % MT_N] ^ (y >> 1);
        if (y & 1u) {
            next ^= 0x9908b0dfu;
        }
        mt->state[i] = next;
    }
    mt->index = 0;
}

uint32_t mt_next_u32(MtState *mt)
{
    if (mt->index >= MT_N) {
        mt_twist(mt);
    }

    uint32_t y = mt->state[mt->index];
    mt->index++;

    y ^= (y >> 11);
    y ^= (y << 7)  & 0x9d2c5680u;
    y ^= (y << 15) & 0xefc60000u;
    y ^= (y >> 18);
    return y;
}

double mt_next_double(MtState *mt)
{
    uint32_t a = mt_next_u32(mt) >> 5;   
    uint32_t b = mt_next_u32(mt) >> 6;   
    return (a * 67108864.0 + b) / 9007199254740992.0;   
}
