#include "include/bench_rsa.h"

#include "board.h"

struct rsa_bench_params_t {
    rsa_t pub;
    rsa_t priv;
    uint8_t* input;
    uint8_t output[RELIC_BN_BITS / 8 + 1];
    int in_len;
    int out_len;
};

bool rsa_bench_iteration(void* args) {
    struct rsa_bench_params_t *params = args;

    int err = cp_rsa_enc(params->output, &params->out_len, params->input, params->in_len, params->pub);

    if (err != STS_OK) {
        printf("Failed to Encrypt: %d\n", err);
        return false;
    }

    return true;
}

static inline int min(int a, int b) {
    return a < b ? a : b;
}

void rsa_bench_after_iteration(void* args) {
    struct rsa_bench_params_t *params = args;
    memcpy(params->input, params->output, min(params->in_len, params->out_len));
    params->out_len = RELIC_BN_BITS / 8 + 1;
}

void bench_rsa(int n_iterations, int n_rsa_block_size) {
    struct benchmark_t bench;

    bench.iteration_func = rsa_bench_iteration;
    bench.after_iteration_func = rsa_bench_after_iteration;

    struct rsa_bench_params_t params = {
        .input = malloc(n_rsa_block_size),
        .in_len = n_rsa_block_size,
        .out_len = RELIC_BN_BITS / 8 + 1,
    };

    rsa_null(params.pub);
    rsa_null(params.priv);

    rsa_new(params.pub);
    rsa_new(params.priv);

    if (cp_rsa_gen(params.pub, params.priv, RELIC_BN_BITS) != STS_OK) {
        free(params.input);
        rsa_free(params.pub);
        rsa_free(params.priv);

        return;
    }

    rand_bytes(params.input, params.in_len);

    if (!run_benchmark(&bench, n_iterations, &params)) {
        return;
    }

    printf("Board: %s\n", RIOT_BOARD);
    printf("MCU: %s\n", RIOT_MCU);
    printf("RSA Benchmark Summary");
    printf("RSA Bits: %d\n", RELIC_BN_BITS);
#if CP_RSAPD == BASIC
    printf("RSA Padding: Basic\n");
#elif CP_RSAPD == PKCS1
	printf("RSA Padding: PKCS1\n");
#elif CP_RSAPD == PKCS2
	printf("RSA Padding: PKCS2\n");
#endif
    printf("Input Size: %d Bytes\n", n_rsa_block_size);
    print_bench_results(&bench);

    free(params.input);
}