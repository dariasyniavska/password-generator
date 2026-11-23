#ifndef MT19937_H
#define MT19937_H

#include <stdint.h>

#define MT_N 624

typedef struct {
    uint32_t state[MT_N];
    int index;
} MtState;

void mt_seed(MtState *mt, uint32_t seed);

void mt_seed_array(MtState *mt, const uint32_t key[], int key_len);

uint32_t mt_next_u32(MtState *mt);

double mt_next_double(MtState *mt);

#endif
