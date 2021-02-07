#include "include/bench.h"

#include "xtimer.h"

void print_bench_results(struct benchmark_t *bench)
{
    printf(" # of Iterations: %d\n", bench->n_iterations);
    printf(" Total usec: %d\n", (int)bench->total);
    printf(" Average usec: %f\n", bench->avg);
    printf(" Min usec: %d\n", (int)bench->min);
    printf(" Max usec: %d\n", (int)bench->max);
}

bool run_benchmark(struct benchmark_t *result_ptr, int n_iterations, void *args)
{
    if (!result_ptr->iteration_func)
    {
        return false;
    }

    result_ptr->n_iterations = n_iterations;
    result_ptr->min = UINT64_MAX;
    result_ptr->max = 0;
    result_ptr->total = 0;

    for (int i = 0; i < n_iterations; i++)
    {
        uint64_t start = xtimer_now_usec64();
        bool result = result_ptr->iteration_func(args);
        uint64_t end = xtimer_now_usec64();

        if (result_ptr->after_iteration_func)
        {
            result_ptr->after_iteration_func(args);
        }

        if (!result)
        {
            return false;
        }

        uint64_t dur = end - start;

        if (dur < result_ptr->min)
        {
            result_ptr->min = dur;
        }

        if (dur > result_ptr->max)
        {
            result_ptr->max = dur;
        }

        result_ptr->total += dur;
    }

    result_ptr->avg = ((float)result_ptr->total) / ((float)n_iterations);
    return true;
}