#include "base64.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

static void base64_encode_block(void *data, char *output, size_t remaining)
{
    static const char *base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    const uint8_t *raw = (uint8_t *)data;

    const bool do_s3 = remaining >= 2;
    const bool do_s4 = remaining >= 3;

#define T(r) base64_table[r]

#define S1(r) (r[0] >> 2)
#define S2(r) (((r[0] & 0x03) << 4) | (do_s3 ? (r[1] >> 4) : (0)))
#define S3(r) (do_s3 ? (((r[1] & 0x0F) << 2) | (do_s4 ? (r[2] >> 6) : (0))) : (64))
#define S4(r) (do_s4 ? (r[2] & ~0xC0) : (64))

    output[0] = T(S1(raw));
    output[1] = T(S2(raw));
    output[2] = T(S3(raw));
    output[3] = T(S4(raw));
}

void base64_encode(void *data, size_t len, char *output)
{
    size_t blocks = BASE64_REQUIRED_BLOCKS(len);

    for (size_t block = 0; block < blocks; block++)
    {
        base64_encode_block((char *)data + (3 * block), output + (4 * block), len - block * 3);
    }
}