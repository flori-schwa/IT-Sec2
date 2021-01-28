#include <stdio.h>

#include <string.h>

#include "crypto/modes/cbc.h"
#include "crypto/ciphers.h"
#include "crypto/aes.h"

#include "shell.h"
#include "random.h"
#include "xtimer.h"

#include "board.h"

#define STR_EQ(a, b) strcmp(a, b) == 0

uint8_t key[AES_KEY_SIZE] = {
    0x64, 0x52, 0x67, 0x55,
    0x6B, 0x58, 0x70, 0x32,
    0x73, 0x35, 0x75, 0x38,
    0x78, 0x2F, 0x41, 0x3F};

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

struct aes_ecb_bench_params_t
{
    cipher_t cipher;
    uint8_t *input;
    uint8_t *output;
    int n_blocks;
    size_t total_buf_len;
};

struct aes_cbc_bench_params_t
{
    cipher_t cipher;
    uint8_t *input;
    uint8_t *output;
    int n_blocks;
    size_t total_buf_len;
    uint8_t iv[16];
};

static void print_bench_results(struct benchmark_t *bench)
{
    printf(" # of Iterations: %d\n", bench->n_iterations);
    printf(" Total usec: %d\n", (int)bench->total);
    printf(" Average usec: %f\n", bench->avg);
    printf(" Min usec: %d\n", (int)bench->min);
    printf(" Max usec: %d\n", (int)bench->max);
}

static bool run_benchmark(struct benchmark_t *result_ptr, int n_iterations, void *args)
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

bool aes_ecb_bench_iteration(void *args)
{
    struct aes_ecb_bench_params_t *params = args;

    int err;
    int block = 0;

    for (size_t offset = 0; block < params->n_blocks; offset = AES_BLOCK_SIZE * ++block)
    {
        err = cipher_encrypt(&params->cipher, params->input + offset, params->output + offset);

        if (err != 1)
        {
            break;
        }
    }

    if (err != 1)
    {
        printf("Failed to Encrypt: %d\n", err);
        return false;
    }

    return true;
}

void aes_ecb_bench_after_iteration(void *args)
{
    struct aes_ecb_bench_params_t *params = args;
    memcpy(params->input, params->output, params->total_buf_len);
}

void bench_aes_ecb(int n_iterations, int n_blocks)
{

    /*
     * Board: iotlab-m3
     *  MCU: stm32
     *  AES-ECB Benchmark Summary:
     *  Using normal loops
     *  Calculating T-Tables on the fly
     *  # of blocks: 16 ( = 256 Bytes)
     *  # of Iterations: 10000
     *  Total usec: 6952951
     *  Average usec: 695.295105
     *  Min usec: 695
     *  Max usec: 703
     */

    struct benchmark_t bench;

    bench.iteration_func = aes_ecb_bench_iteration;
    bench.after_iteration_func = aes_ecb_bench_after_iteration;

    struct aes_ecb_bench_params_t params = {
        .n_blocks = n_blocks,
        .total_buf_len = n_blocks * AES_BLOCK_SIZE};

    params.input = malloc(params.total_buf_len);
    params.output = malloc(params.total_buf_len);

    int err = cipher_init(&params.cipher, CIPHER_AES_128, key, AES_KEY_SIZE);

    if (err != CIPHER_INIT_SUCCESS)
    {
        printf("Failed to init cipher: %d\n", err);
        return;
    }

    random_bytes(params.input, params.total_buf_len);

    if (!run_benchmark(&bench, n_iterations, &params))
    {
        return;
    }

    printf("Board: %s\n", RIOT_BOARD);
    printf("MCU: %s\n", RIOT_MCU);
    printf("AES-ECB Benchmark Summary:\n");
#ifdef MODULE_CRYPTO_AES_UNROLL
    printf(" Using unrolled loops\n");
#else
    printf(" Using normal loops\n");
#endif

#ifdef MODULE_CRYPTO_AES_PRECALCULATED
    printf(" Using Precalculated T-Tables\n");
#else
    printf(" Calculating T-Tables on the fly\n");
#endif

    printf(" # of blocks: %d ( = %d Bytes)\n", n_blocks, n_blocks * AES_BLOCK_SIZE);
    print_bench_results(&bench);

    free(params.input);
    free(params.output);
}

bool aes_cbc_bench_iteration(void *args)
{
    struct aes_cbc_bench_params_t *params = args;

    int err = cipher_encrypt_cbc(&params->cipher, params->iv, params->input, params->total_buf_len, params->output);

    if (err < 0)
    {
        printf("Failed to Encrypt: %d\n", err);
        return false;
    }

    return true;
}

void aes_cbc_after_iteration(void *args)
{
    struct aes_cbc_bench_params_t *params = args;

    for (int block = 0; block < params->n_blocks; block++)
    {
        for (int i = 0; i < 16; i++)
        {
            params->iv[i] ^= params->output[block * AES_BLOCK_SIZE + i];
        }
    }

    memcpy(params->input, params->output, params->total_buf_len);
}

void bench_aes_cbc(int n_iterations, int n_blocks)
{

    /*
     * Board: iotlab-m3
     * MCU: stm32
     * AES-CBC Benchmark Summary:
     *  Using normal loops
     *  Calculating T-Tables on the fly
     *  # of blocks: 16 ( = 256 Bytes)
     *  # of Iterations: 10000
     *  Total usec: 7691615
     *  Average usec: 769.161499
     *  Min usec: 769
     *  Max usec: 777
     */

    struct benchmark_t bench;

    bench.iteration_func = aes_cbc_bench_iteration;
    bench.after_iteration_func = aes_cbc_after_iteration;

    struct aes_cbc_bench_params_t params = {
        .n_blocks = n_blocks,
        .total_buf_len = n_blocks * AES_BLOCK_SIZE};

    params.input = malloc(params.total_buf_len);
    params.output = malloc(params.total_buf_len);

    int err = cipher_init(&params.cipher, CIPHER_AES_128, key, AES_KEY_SIZE);

    if (err != CIPHER_INIT_SUCCESS)
    {
        printf("Failed to init cipher: %d\n", err);
        return;
    }

    random_bytes(params.iv, 16);
    random_bytes(params.input, params.total_buf_len);

    if (!run_benchmark(&bench, n_iterations, &params))
    {
        return;
    }

    printf("Board: %s\n", RIOT_BOARD);
    printf("MCU: %s\n", RIOT_MCU);
    printf("AES-CBC Benchmark Summary:\n");
#ifdef MODULE_CRYPTO_AES_UNROLL
    printf(" Using unrolled loops\n");
#else
    printf(" Using normal loops\n");
#endif

#ifdef MODULE_CRYPTO_AES_PRECALCULATED
    printf(" Using Precalculated T-Tables\n");
#else
    printf(" Calculating T-Tables on the fly\n");
#endif

    printf(" # of blocks: %d ( = %d Bytes)\n", n_blocks, n_blocks * AES_BLOCK_SIZE);
    print_bench_results(&bench);

    free(params.input);
    free(params.output);
}

int bench_command(int argc, char **argv)
{
    if (argc < 3)
    {
        printf("Syntax: \n");
        printf(" - %s aes-ecb <iterations> [blocks]\n", argv[0]);
        printf(" - %s aes-cbc <iterations> [blocks]\n", argv[0]);

        return 1;
    }

    int n_iterations;

    if (sscanf(argv[2], "%d", &n_iterations) != 1)
    {
        printf("Could not parse iteration count\n");
        return 1;
    }

    int n_blocks = 4;

    if (argc >= 4)
    {
        if (sscanf(argv[3], "%d", &n_blocks) != 1)
        {
            printf("Could not parse block count\n");
        }
    }

    if (STR_EQ("aes-ecb", argv[1]))
    {
        bench_aes_ecb(n_iterations, n_blocks);
    }
    else if (STR_EQ("aes-cbc", argv[1]))
    {
        bench_aes_cbc(n_iterations, n_blocks);
    }
    else
    {
        printf("Unknown command: %s\n", argv[1]);
        return 1;
    }

    return 0;
}

int main(void)
{
    shell_command_t commands[] = {
        {"bench", "Benchmark Crypto Algorithms", bench_command},
        {NULL, NULL, NULL}};

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
