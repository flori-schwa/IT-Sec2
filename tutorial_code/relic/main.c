#include <stdio.h>

#include <relic.h>

#include "base64.h"
#include "der.h"

#include "od.h"

void print_pub_key(rsa_t pub)
{
    der_buffer seq_body_buffer;
    der_buf_init(&seq_body_buffer);

    der_write_var_int(&seq_body_buffer, pub->n->used * sizeof(dig_t), (uint8_t *)pub->n->dp);
    der_write_var_int(&seq_body_buffer, pub->e->used * sizeof(dig_t), (uint8_t *)pub->e->dp);

    der_buffer seq_head = der_tag_header(CONSTRUCTED(DER_SEQUENCE), seq_body_buffer.used);

    size_t total_len = seq_body_buffer.used + seq_head.used;

    der_buffer final_buf = {
        .buf = malloc(total_len),
        .capacity = total_len,
        .used = 0};

    memcpy(final_buf.buf, seq_head.buf, seq_head.used);
    final_buf.used += seq_head.used;

    memcpy(final_buf.buf + seq_head.used, seq_body_buffer.buf, seq_body_buffer.used);
    final_buf.used += seq_body_buffer.used;

    free(seq_body_buffer.buf);
    free(seq_head.buf);

    size_t b64_str_len = BASE64_REQUIRED_LENGTH(final_buf.used);
    char *base64 = calloc(b64_str_len + 1, sizeof(char));

    base64_encode(final_buf.buf, final_buf.used, base64);

    printf("-----BEGIN PUBLIC KEY-----\n");

    for (size_t block = 0; block < b64_str_len / 64; block++)
    {
        for (int i = 0; i < 64; i++)
        {
            putc(base64[(block * 64) + i], stdout);
        }

        putc('\n', stdout);
    }

    if (b64_str_len % 64)
    {
        size_t offset = b64_str_len - (b64_str_len % 64);

        while (offset < b64_str_len)
        {
            putc(base64[offset++], stdout);
        }

        putc('\n', stdout);
    }

    printf("-----END PUBLIC KEY-----\n");

    free(base64);
}

int rsa(void)
{
    int code = STS_ERR;

    rsa_t pub, priv;
    uint8_t in[10], out[RELIC_BN_BITS / 8 + 1], h[MD_LEN];
    int i1, o1;
    int result;

    rsa_null(pub);
    rsa_null(priv);

    //TRY {
    rsa_new(pub);
    rsa_new(priv);

    result = cp_rsa_gen(pub, priv, RELIC_BN_BITS);

    // Public Key components: n, e
    // Private Key components: d
    rand_bytes(in, 10);

    print_pub_key(pub);
    //} CATCH_ANY {
    //    ERROR(end);
    //}

    //end:
    rsa_free(pub);
    rsa_free(priv);

    (void)result;
    (void)o1;
    (void)i1;
    (void)h;
    (void)out;
    (void)code;

    return 0;
}

int main(void)
{
    core_init();
    int res =  rsa();
    core_clean();

    return res;
}
