#include "include/bench_aes.h"

#include "board.h"
#include "crypto/modes/cbc.h"

#include <stdbool.h>

static uint8_t key[AES_KEY_SIZE] = {
    0x64, 0x52, 0x67, 0x55,
    0x6B, 0x58, 0x70, 0x32,
    0x73, 0x35, 0x75, 0x38,
    0x78, 0x2F, 0x41, 0x3F};

struct aes_cbc_bench_params_t
{
    cipher_t cipher;
    uint8_t *input;
    uint8_t *output;
    int n_blocks;
    size_t total_buf_len;
    uint8_t iv[16];
};

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
Board: iotlab-m3
MCU: stm32
AES-CBC Benchmark Summary:
 Using normal loops
 Calculating T-Tables on the fly
 # of blocks: 4 ( = 64 Bytes)
 # of Iterations: 10000
 Total usec: 1890092
 Average usec: 189.009201
 Min usec: 188
 Max usec: 196
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

    rand_bytes(params.iv, 16);
    rand_bytes(params.input, params.total_buf_len);

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