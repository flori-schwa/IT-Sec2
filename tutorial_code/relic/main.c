#include <stdio.h>

#include <relic.h>

#include "base64.h"
#include "der.h"

#include "od.h"

void pem_print(const char *label, const char *base64)
{
    printf("-----BEGIN %s-----\n", label);

    size_t b64_str_len = strlen(base64);

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

    printf("-----END %s-----\n", label);
}

void der_write_bn_t(der_buffer_t *buffer, bn_t bn)
{
    if (bn->used == 0) {
        der_write_uint8_t(buffer, 0);
        return;
    }

    int first_dig_required_bytes;

    for (int byte = (WORD / 8) - 1; byte >= 0; byte--) {
        if (bn->dp[bn->used - 1] & (0xFF << (byte * 8))) {
            first_dig_required_bytes = byte + 1;
            break;
        }
    }

    size_t required_len = ((WORD / 8) * (bn->used - 1)) // used - 1 digits
                        + first_dig_required_bytes;
    bool leading_zero = false;

    if (bn->dp[bn->used - 1] & (0x80 << (WORD - 8))) {
        required_len++;
        leading_zero = true;
    }

    der_write_tag_header(buffer, DER_INT, required_len);
    der_buf_ensure_capacity(buffer, required_len);

    if (leading_zero) {
        buffer->buf[buffer->used++] = 0;
    }

    for (int byte = first_dig_required_bytes - 1; byte >= 0; byte--) {
        buffer->buf[buffer->used++] = (bn->dp[bn->used - 1] & (0xFF << (byte * 8))) >> (byte * 8);
    }

    for (int i = bn->used - 2; i >= 0; i--) {
        for (int byte = (WORD / 8) - 1; byte >= 0; byte--) {
            buffer->buf[buffer->used++] = (bn->dp[i] & (0xFF << (byte * 8))) >> (byte * 8);
        }
    }
}

static const uint8_t rsa_oid_sequence[15] = {
    0x30,                                                 // Sequence Tag
    0x0D,                                                 // Sequence Tag Length
    0x06,                                                 // Object Identifier Tag
    0x09,                                                 // Object Identifier Tag Length
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, // Object Identifier (1.2.840.113549.1.1.1 - RSA encryption)
    0x05, 0x00                                            // Null Tag
};

void print_pub_key(rsa_t pub)
{
    der_buffer_t pub_key_body_buffer;
    der_buf_init(&pub_key_body_buffer);

    der_write_bn_t(&pub_key_body_buffer, pub->n);
    der_write_bn_t(&pub_key_body_buffer, pub->e);

    der_buffer_t public_key = der_buf_build_sequence(&pub_key_body_buffer);
    free(pub_key_body_buffer.buf);

    der_buffer_t seq_body_buffer;
    der_buf_init(&seq_body_buffer);

    der_buf_ensure_capacity(&seq_body_buffer, 15);
    memcpy(seq_body_buffer.buf + seq_body_buffer.used, rsa_oid_sequence, 15);
    seq_body_buffer.used += 15;

    der_write_tag_header(&seq_body_buffer, DER_BIT_STRING, public_key.used + 1); // +1 for Unused field

    seq_body_buffer.buf[seq_body_buffer.used] = 0; // 0 unused bits
    seq_body_buffer.used++;
    der_buf_ensure_capacity(&seq_body_buffer, public_key.used);
    memcpy(seq_body_buffer.buf + seq_body_buffer.used, public_key.buf, public_key.used);
    seq_body_buffer.used += public_key.used;

    free(public_key.buf);

    der_buffer_t final = der_buf_build_sequence(&seq_body_buffer);
    free(seq_body_buffer.buf);

    size_t b64_str_len = BASE64_REQUIRED_LENGTH(final.used);
    char *base64 = calloc(b64_str_len + 1, sizeof(char));

    base64_encode(final.buf, final.used, base64);

    pem_print("PUBLIC KEY", base64);    

    free(base64);
    free(final.buf);
}

void print_priv_key(rsa_t pub, rsa_t priv)
{
    der_buffer_t priv_key_body_buffer;
    der_buf_init(&priv_key_body_buffer);

    der_write_uint8_t(&priv_key_body_buffer, 0); // two-prime
    der_write_bn_t(&priv_key_body_buffer, priv->n);
    der_write_bn_t(&priv_key_body_buffer, pub->e);
    der_write_bn_t(&priv_key_body_buffer, priv->d);
    der_write_bn_t(&priv_key_body_buffer, priv->p);
    der_write_bn_t(&priv_key_body_buffer, priv->q);
    der_write_bn_t(&priv_key_body_buffer, priv->dp);
    der_write_bn_t(&priv_key_body_buffer, priv->dq);
    der_write_bn_t(&priv_key_body_buffer, priv->qi);

    der_buffer_t private_key = der_buf_build_sequence(&priv_key_body_buffer);

    size_t b64_str_len = BASE64_REQUIRED_LENGTH(private_key.used);
    char *base64 = calloc(b64_str_len + 1, sizeof(char));

    base64_encode(private_key.buf, private_key.used, base64);

    pem_print("RSA PRIVATE KEY", base64);    

    free(base64);
    free(private_key.buf);
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
    print_priv_key(pub, priv);
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
    int res = rsa();
    core_clean();

    return res;
}
