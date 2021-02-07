#ifndef BENCH_AES_H
#define BENCH_AES_H

#include "bench.h"

#include "crypto/ciphers.h"
#include "crypto/aes.h"

void bench_aes_ecb(int n_iterations, int n_blocks);

void bench_aes_cbc(int n_iterations, int n_blocks);

#endif /* BENCH_AES_H */