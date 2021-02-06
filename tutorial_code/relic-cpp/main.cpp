#include "shell.h"
#include "od.h"

extern "C" {
    #include "relic.h"
}

#include "base64.h"

#include <cstdio>
#include "der.hpp"

const uint8_t rsa_oid_sequence[15] = {
    0x30,                                                 // Sequence Tag
    0x0D,                                                 // Sequence Tag Length
    0x06,                                                 // Object Identifier Tag
    0x09,                                                 // Object Identifier Tag Length
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, // Object Identifier (1.2.840.113549.1.1.1 - RSA encryption)
    0x05, 0x00                                            // Null Tag
};

void pem_print(const char *label, const char *base64, const size_t b64_str_len)
{
    printf("-----BEGIN %s-----\n", label);

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

static int bn_most_significant_byte(bn_t bn)
{
    if (bn->used == 0)
    {
        return -1;
    }

    for (int byte = (WORD / 8) - 1; byte >= 0; byte--)
    {
        if (bn->dp[bn->used - 1] & (0xFF << (byte * 8)))
        {
            return byte;
        }
    }

    return -1;
}

size_t der_bn_value_len(bn_t bn, int *first_dig_required_bytes, bool *leading_zero)
{
    if (bn->used == 0)
    {
        return DerBuffer::tag_size(DerBuffer::uint8_value_len(0));
    }

    // The amount of Bytes required to encode the (In Big-Endian Order) First Digit of the multiple precision integer
    int fdrb = bn_most_significant_byte(bn) + 1;

    if (first_dig_required_bytes)
    {
        *first_dig_required_bytes = fdrb;
    }

    size_t required_len = ((WORD / 8) * (bn->used - 1)) // used - 1 full size digits
                          + fdrb;                       // Most Significant Digit without leading zeros

    if (bn->dp[bn->used - 1] & (0x80 << (WORD - 8)))
    {
        required_len++;

        if (leading_zero)
        {
            *leading_zero = true;
        }
    }

    return required_len;
}

void der_write_bn_t(DerBuffer *buffer, bn_t bn)
{
    if (bn->used == 0)
    {
        buffer->write_uint8(0);
        return;
    }

    int first_dig_required_bytes;
    bool leading_zero = false;
    size_t required_len = der_bn_value_len(bn, &first_dig_required_bytes, &leading_zero);

    buffer->write_tag_header(DER_INT, required_len);
    buffer->ensure_capacity(required_len);

    if (leading_zero)
    {
        buffer->append_raw(0);
    }

    for (int byte = first_dig_required_bytes - 1; byte >= 0; byte--)
    {

        buffer->append_raw(NTH_BYTE(bn->dp[bn->used - 1], byte));
    }

    for (int i = bn->used - 2; i >= 0; i--)
    {
        for (int byte = (WORD / 8) - 1; byte >= 0; byte--)
        {
            buffer->append_raw(NTH_BYTE(bn->dp[i], byte));
        }
    }
}

void print_pub_key(rsa_t pub)
{
    /* ================== Length Calculations ================== */

    size_t tag_n_len = DerBuffer::tag_size(der_bn_value_len(pub->n, NULL, NULL));
    size_t tag_e_len = DerBuffer::tag_size(der_bn_value_len(pub->e, NULL, NULL));

    size_t pub_key_sequence_length = DerBuffer::tag_size(tag_n_len + tag_e_len);

    size_t bit_str_tag_len = DerBuffer::tag_size(pub_key_sequence_length + 1); // +1 for Bit Strings unused bits field

    size_t rsa_oid_seq_tag_len = 15; // See Above

    size_t total_asn_len = DerBuffer::tag_size(rsa_oid_seq_tag_len + bit_str_tag_len);

    /* ================== Initializing Buffer ================== */

    DerBuffer der;
    der.ensure_capacity(total_asn_len);

    /* ================== Writing Data ================== */

    // Sequence containing OID Sequence and Bit String
    der.write_tag_header(CONSTRUCTED(DER_SEQUENCE), rsa_oid_seq_tag_len + bit_str_tag_len);

    // OID Sequence Tag containing OID and NULL Tag
    der.write(rsa_oid_sequence, 15);

    // Bit String Tag
    der.write_tag_header(DER_BIT_STRING, pub_key_sequence_length + 1);
    der.append_raw(0); // Unused Bits field

    // Sequence Tag containing both pubkey integers n and e
    der.write_tag_header(CONSTRUCTED(DER_SEQUENCE), tag_n_len + tag_e_len);

    der_write_bn_t(&der, pub->n);
    der_write_bn_t(&der, pub->e);

    /* ================== Base64 Encode and PEM Output ================== */

    size_t b64_str_len = BASE64_REQUIRED_LENGTH(der.used);
    char *base64 = (char *)malloc(b64_str_len * sizeof(char));

    base64_encode(der.buf, der.used, base64);

    pem_print("PUBLIC KEY", base64, b64_str_len);

    free(base64);
}

void print_priv_key(rsa_t pub, rsa_t priv)
{
    /* ================== Length Calculations ================== */

    size_t version_tag_len = DerBuffer::tag_size(DerBuffer::uint8_value_len(0));

    size_t tag_n_len = DerBuffer::tag_size(der_bn_value_len(priv->n, NULL, NULL));
    size_t tag_e_len = DerBuffer::tag_size(der_bn_value_len(pub->e, NULL, NULL));
    size_t tag_d_len = DerBuffer::tag_size(der_bn_value_len(priv->d, NULL, NULL));
    size_t tag_p_len = DerBuffer::tag_size(der_bn_value_len(priv->p, NULL, NULL));
    size_t tag_q_len = DerBuffer::tag_size(der_bn_value_len(priv->q, NULL, NULL));
    size_t tag_dp_len = DerBuffer::tag_size(der_bn_value_len(priv->dp, NULL, NULL));
    size_t tag_dq_len = DerBuffer::tag_size(der_bn_value_len(priv->dq, NULL, NULL));
    size_t tag_qi_len = DerBuffer::tag_size(der_bn_value_len(priv->qi, NULL, NULL));

    size_t sequence_value_length = version_tag_len + tag_n_len + tag_e_len + tag_d_len + tag_p_len + tag_q_len + tag_dp_len + tag_dq_len + tag_qi_len;

    size_t total_asn_len = DerBuffer::tag_size(sequence_value_length);

    /* ================== Initializing Buffer ================== */

    DerBuffer der;
    der.ensure_capacity(total_asn_len);

    /* ================== Writing Data ================== */

    der.write_tag_header(CONSTRUCTED(DER_SEQUENCE), sequence_value_length);

    der.write_uint8(0);
    der_write_bn_t(&der, priv->n);
    der_write_bn_t(&der, pub->e);
    der_write_bn_t(&der, priv->d);
    der_write_bn_t(&der, priv->p);
    der_write_bn_t(&der, priv->q);
    der_write_bn_t(&der, priv->dp);
    der_write_bn_t(&der, priv->dq);
    der_write_bn_t(&der, priv->qi);

    /* ================== Base64 Encode and PEM Output ================== */

    size_t b64_str_len = BASE64_REQUIRED_LENGTH(der.used);
    char *base64 = (char *)malloc(b64_str_len * sizeof(char));

    base64_encode(der.buf, der.used, base64);

    pem_print("RSA PRIVATE KEY", base64, b64_str_len);

    free(base64);
}

static rsa_t pub, priv;

static int rsa_encrypt(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Syntax: %s payload\n", argv[0]);
        return 1;
    }

    uint8_t out[RELIC_BN_BITS / 8 + 1];

    int out_len = RELIC_BN_BITS / 8 + 1;
    int result = cp_rsa_enc(out, &out_len, (uint8_t *)argv[1], strlen(argv[1]), pub);

    printf("cp_rsa_enc return code is %d\n", result);

    size_t b64_str_len = BASE64_REQUIRED_LENGTH(out_len);
    char *base64 = (char *)malloc(b64_str_len * sizeof(char));
    base64_encode(out, out_len, base64);

    pem_print("RSA ENCRYPTED TEXT", base64, b64_str_len);

    free(base64);

    return 0;
}

int main(void)
{
    core_init();

    rsa_null(pub);
    rsa_null(priv);

    rsa_new(pub);
    rsa_new(priv);

    cp_rsa_gen(pub, priv, RELIC_BN_BITS);

    print_pub_key(pub);
    printf("\n");
    print_priv_key(pub, priv);
    printf("\n");

    shell_command_t commands[] = {
        {"rsa", "RSA encrypt text", rsa_encrypt},
        {NULL, NULL, NULL}};

    char shell_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(commands, shell_buf, SHELL_DEFAULT_BUFSIZE);

    rsa_free(pub);
    rsa_free(priv);

    core_clean();

    return 0;
}
