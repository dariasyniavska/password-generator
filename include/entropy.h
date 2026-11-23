#ifndef ENTROPY_H
#define ENTROPY_H

#include <stddef.h>
#include "mt19937.h"

int os_random_bytes(void *buf, size_t n);

void mt_seed_from_os(MtState *mt);

#endif
