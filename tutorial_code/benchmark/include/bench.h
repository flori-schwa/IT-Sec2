#ifndef BENCH_H
#define BENCH_H

#include "relic.h"

#include <stdint.h>
#include <stdbool.h>

typedef bool (*bench_func)(void *args);
typedef void (*after_iter_func)(void *args);

struct benchmark_t
{
    int n_iterations;
    uint64_t min;
    uint64_t max;
    uint64_t total;
    float avg;
    bench_func iteration_func;
    after_iter_func after_iteration_func;
};

void print_bench_results(struct benchmark_t *bench);

bool run_benchmark(struct benchmark_t *result_ptr, int n_iterations, void *args);

#endif /* BENCH_H */