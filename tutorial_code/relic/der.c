#include "der.h"

#include <stdlib.h>
#include <stdio.h>

void der_buf_init(der_buffer *buf)
{
    buf->buf = NULL;
    buf->capacity = 0;
    buf->used = 0;
}

void der_buf_ensure_capacity(der_buffer *buffer, size_t offset, size_t length)
{
    if (!buffer->buf)
    {
        buffer->buf = malloc(offset + length);
        buffer->capacity = offset + length;
    }
    else
    {
        if (buffer->capacity < (offset + length)) {
            buffer->buf = realloc(buffer->buf, offset + length);
            buffer->capacity = offset + length;
        }
    }
}

static int size_t_msbyte(size_t x)
{
    const uint8_t *bytes = (uint8_t *)&x;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    for (int byte = sizeof(size_t) - 1; byte >= 0; byte--)
    {
        if (bytes[byte])
        {
            return byte;
        }
    }
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    for (int byte = 0; byte < sizeof(size_t); byte++)
    {
        if (byte[byte])
        {
            return byte;
        }
    }
#else
#error Unknown Endianness
#endif

    return 0;
}

static void size_t_write_big_endian(der_buffer *buffer, size_t x, int max)
{
    if ((size_t)max > sizeof(size_t))
    {
        return;
    }

    der_buf_ensure_capacity(buffer, buffer->used, max);

    const uint8_t *bytes = (uint8_t *)&x;

    for (int i = 0; i < max; i++)
    {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        buffer->buf[buffer->used + i] = bytes[sizeof(size_t) - 1 - i];
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        buffer->buf[buffer->used + i] = bytes[i];
#else
#error Unknown Endianness
#endif
    }

    buffer->used += max;
}

der_buffer der_tag_header(uint8_t type, size_t content_length)
{
    der_buffer buffer = {NULL, 0, 0};

    if (content_length > 127)
    {
        int lf_int_bytes = size_t_msbyte(content_length) + 1;

        if (lf_int_bytes > 127)
        {
            printf("Content way too long: %zu\n", content_length);
            return buffer;
        }

        der_buf_init(&buffer);
        der_buf_ensure_capacity(&buffer, 0, 2);

        buffer.buf[0] = type;
        buffer.buf[1] = 0x80 | lf_int_bytes;
        buffer.used += 2;

        size_t_write_big_endian(&buffer, content_length, lf_int_bytes);
    }
    else
    {
        der_buf_init(&buffer);
        der_buf_ensure_capacity(&buffer, 0, 2);

        buffer.buf[0] = type;
        buffer.buf[1] = (uint8_t)content_length;
        buffer.used += 2;
    }

    return buffer;
}

der_buffer der_sequence_tag(size_t length)
{
    return der_tag_header(CONSTRUCTED(DER_SEQUENCE), length);
}

void der_write_var_int(der_buffer *buf, uint8_t length, uint8_t *int_buf)
{
    der_buffer header = der_tag_header(DER_INT, length);

    if (!header.buf)
    {
        return;
    }

    der_buf_ensure_capacity(buf, buf->used, header.used);

    memcpy(buf->buf + buf->used, header.buf, header.used);
    buf->used += header.used;
    free(header.buf);

    der_buf_ensure_capacity(buf, buf->used, length);

    for (size_t i = 0; i < length; i++)
    {
        buf->buf[buf->used + i] = int_buf[length - 1 - i]; // Big Endian
    }

    buf->used += length;
}