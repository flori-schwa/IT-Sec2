#include "random.h"

#include <stdio.h>

#include <string.h>

#include "shell.h"

#include "board.h"

#include "include/bench.h"
#include "include/bench_aes.h"
#include "include/bench_rsa.h"

#define STR_EQ(a, b) strcmp(a, b) == 0


// Copied from relic_cp_rsa.c

#if CP_RSAPD == PKCS1
#define RSA_PAD_LEN		(11)
#elif CP_RSAPD == PKCS2
#define RSA_PAD_LEN		(2 * MD_LEN + 2)
#else
#define RSA_PAD_LEN		(2)
#endif


int bench_command(int argc, char **argv)
{
    if (argc < 3)
    {
        printf("Syntax: \n");
        printf(" - %s aes-ecb <iterations> [blocks]\n", argv[0]);
        printf(" - %s aes-cbc <iterations> [blocks]\n", argv[0]);
        printf(" - %s rsa <iterations> [block size]\n", argv[0]);

        return 1;
    }

    int n_iterations;

    if (sscanf(argv[2], "%d", &n_iterations) != 1)
    {
        printf("Could not parse iteration count\n");
        return 1;
    }

    int rsa_block_size = 128 - RSA_PAD_LEN;
    int n_blocks = 4;

    if (argc >= 4)
    {
        if (sscanf(argv[3], "%d", &n_blocks) != 1)
        {
            printf("Could not parse block count\n");
        } else {
            rsa_block_size = n_blocks;
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
    else if (STR_EQ("rsa", argv[1])) {
        bench_rsa(n_iterations, rsa_block_size);
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
    core_init();

    shell_command_t commands[] = {
        {"bench", "Benchmark Crypto Algorithms", bench_command},
        {NULL, NULL, NULL}};

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    core_clean();

    return 0;
}
