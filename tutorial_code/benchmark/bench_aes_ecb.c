#include "include/bench_aes.h"

#include "board.h"

#include <stdbool.h>

static uint8_t key[AES_KEY_SIZE_128] = {
    0x64, 0x52, 0x67, 0x55,
    0x6B, 0x58, 0x70, 0x32,
    0x73, 0x35, 0x75, 0x38,
    0x78, 0x2F, 0x41, 0x3F};

struct aes_ecb_bench_params_t
{
    cipher_t cipher;
    uint8_t *input;
    uint8_t *output;
    int n_blocks;
    size_t total_buf_len;
};

bool aes_ecb_bench_iteration(void *args)
{
    struct aes_ecb_bench_params_t *params = args;

    int err = 0;
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
Board: iotlab-m3
MCU: stm32
AES-ECB Benchmark Summary:
 Using normal loops
 Calculating T-Tables on the fly
 # of blocks: 4 ( = 64 Bytes)
 # of Iterations: 10000
 Total usec: 1701615
 Average usec: 170.161499
 Min usec: 170
 Max usec: 177
     */

    struct benchmark_t bench;

    bench.iteration_func = aes_ecb_bench_iteration;
    bench.after_iteration_func = aes_ecb_bench_after_iteration;

    struct aes_ecb_bench_params_t params = {
        .n_blocks = n_blocks,
        .total_buf_len = n_blocks * AES_BLOCK_SIZE};

    params.input = malloc(params.total_buf_len);
    params.output = malloc(params.total_buf_len);

    int err = cipher_init(&params.cipher, CIPHER_AES_128, key, AES_KEY_SIZE_128);

    if (err != CIPHER_INIT_SUCCESS)
    {
        printf("Failed to init cipher: %d\n", err);
        return;
    }

    rand_bytes(params.input, params.total_buf_len);

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
