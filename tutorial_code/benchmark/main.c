#include <stdio.h>

#include <string.h>

#include "crypto/ciphers.h"
#include "crypto/aes.h"

#include "shell.h"
#include "random.h"
#include "xtimer.h"

#define STR_EQ(a, b) strcmp(a, b) == 0

static uint8_t key[AES_KEY_SIZE] = {
    0x64, 0x52, 0x67, 0x55,
    0x6B, 0x58, 0x70, 0x32,
    0x73, 0x35, 0x75, 0x38,
    0x78, 0x2F, 0x41, 0x3F};

void bench_aes_ecb(int iterations)
{

    /*
        Board: iotlab-m3
        MCU: stm32

         AES-ECB Benchmark Summary:
         Using unrolled loops
         Using Precalculated T-Tables
         # of Iterations: 10000
         Total usec: 377851
         Average usec: 37000 / 1000
         Min usec: 37
         Max usec: 45

        AES-ECB Benchmark Summary:
         Using normal loops
         Calculating T-Tables on the fly
         # of Iterations: 10000
         Total usec: 442134
         Average usec: 44000 / 1000
         Min usec: 44
         Max usec: 51
    */

    uint64_t min = UINT64_MAX;
    uint64_t max = 0;
    uint64_t total = 0;

    cipher_t cipher;
    int err = cipher_init(&cipher, CIPHER_AES_128, key, AES_KEY_SIZE);

    if (err != CIPHER_INIT_SUCCESS)
    {
        printf("Failed to init cipher: %d\n", err);
        return;
    }

    uint8_t block[AES_BLOCK_SIZE] = {0};
    uint8_t output[AES_BLOCK_SIZE] = {0};

    for (int i = 0; i < iterations; i++)
    {
        random_bytes(block, AES_BLOCK_SIZE);

        uint64_t start = xtimer_now_usec64();
        err = cipher_encrypt(&cipher, block, output);
        uint64_t end = xtimer_now_usec64();

        if (err != 1)
        {
            printf("Failed to Encrypt on Iteration #%d: %d\n", (i + 1), err);
            return;
        }

        uint64_t dur = end - start;

        if (dur < min)
        {
            min = dur;
        }

        if (dur > max)
        {
            max = dur;
        }

        total += dur;
    }

    float avg = ((float)total) / ((float)iterations);

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

    printf(" # of Iterations: %d\n", iterations);
    printf(" Total usec: %d\n", (int) total);
    printf(" Average usec: %d / 1000\n", (int) avg * 1000);
    printf(" Min usec: %d\n", (int) min);
    printf(" Max usec: %d\n", (int) max);
}

void bench_aes_cbc(int iterations, int blocks)
{
    (void)iterations;
    (void)blocks;

    printf("Not yet implemented\n");
}

int bench_command(int argc, char **argv)
{
    if (argc < 3)
    {
        printf("Syntax: \n");
        printf(" - %s aes-ecb <iterations>\n", argv[0]);
        printf(" - %s aes-cbc <iterations> [blocks]\n", argv[0]);

        return 1;
    }

    int n_iterations;

    if (sscanf(argv[2], "%d", &n_iterations) != 1)
    {
        printf("Could not parse iteration count\n");
        return 1;
    }

    if (STR_EQ("aes-ecb", argv[1]))
    {
        bench_aes_ecb(n_iterations);
    }
    else if (STR_EQ("aes-cbc", argv[1]))
    {
        int n_blocks = 4;

        if (argc >= 4)
        {
            if (sscanf(argv[3], "%d", &n_iterations) != 1)
            {
                printf("Could not parse block count\n");
            }
        }

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

    printf("Board: %s\n", RIOT_BOARD);
    printf("MCU: %s\n", RIOT_MCU);

    shell_command_t commands[] = {
        {"bench", "Benchmark Crypto Algorithms", bench_command},
        {NULL, NULL, NULL}};

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
