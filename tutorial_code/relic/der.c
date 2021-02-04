#include "der.h"
#include "od.h"
#include "byteorder.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

void der_write_null_tag(der_buffer_t* buffer) {
    der_buf_ensure_capacity(buffer, 2);

    buffer->buf[buffer->used] = DER_NULL;
    buffer->buf[buffer->used + 1] = 0;

    buffer->used += 2;
}

void der_write_rsa_oid(der_buffer_t* buffer) {
    static const uint8_t rsa_oid[9] = {
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
    };

    der_buffer_t header = der_tag_header(DER_OBJECT_ID, 9);
    
    if (!header.buf) {
        return;
    }

    der_buf_write(buffer, header.buf, header.used);
    free(header.buf);

    der_buf_ensure_capacity(buffer, 9);
    memcpy(buffer->buf + buffer->used, rsa_oid, 9);
    buffer->used += 9;
}

der_buffer_t der_buf_build_sequence(der_buffer_t* body) {
    der_buffer_t head = der_tag_header(CONSTRUCTED(DER_SEQUENCE), body->used);

    size_t total_len = body->used + head.used;

    der_buffer_t final_buf = {
        .buf = malloc(total_len),
        .capacity = total_len,
        .used = 0
    };

    der_buf_write(&final_buf, head.buf, head.used);
    der_buf_write(&final_buf, body->buf, body->used);

    free(head.buf);

    return final_buf;
}

void der_buf_init(der_buffer_t *buf)
{
    buf->buf = NULL;
    buf->capacity = 0;
    buf->used = 0;
}

void der_buf_ensure_capacity(der_buffer_t *buffer, uint32_t length)
{
    uint32_t offset = buffer->used;
    size_t required_total_len = (size_t) (offset + length);

    if (!buffer->buf)
    {
        buffer->buf = malloc(required_total_len);
        buffer->capacity = required_total_len;
    }
    else
    {
        if (buffer->capacity < required_total_len) {
            buffer->buf = realloc(buffer->buf, required_total_len);
            buffer->capacity = required_total_len;
        }
    }
}

void der_buf_write(der_buffer_t* target, void* source, uint32_t length) {
    der_buf_ensure_capacity(target, length);
    memcpy((char*) target->buf + target->used, source, (size_t) length);
    target->used += (size_t) length;
}

static int uint32_t_msbyte(uint32_t x) {
    if (x & 0xFF000000) {
        return 3;
    } else if (x & 0x00FF0000) {
        return 2;
    } else if (x & 0x0000FF00) {
        return 1;
    }

    return 0;
}

static void uint32_t_write_big_endian(der_buffer_t *buffer, uint32_t x, int max) {
    if (max <= 0 || (size_t) max > sizeof(uint32_t)) {
        return;
    }

    der_buf_ensure_capacity(buffer, max);

    for (int byte = max - 1; byte >= 0; byte--) {
        buffer->buf[buffer->used++] = (x & (0xFF << (byte * 8))) >> (byte * 8);
    }
}

bool der_write_tag_header(der_buffer_t* buffer, uint8_t type, uint32_t content_length) {
    if (content_length > 127)
    {
        int lf_int_bytes = uint32_t_msbyte(content_length) + 1;

        if (lf_int_bytes > 127)
        {
            printf("Content way too long: %zu\n", content_length);
            return false;
        }

        der_buf_ensure_capacity(buffer, 2);

        buffer->buf[buffer->used] = type;
        buffer->buf[buffer->used + 1] = 0x80 | lf_int_bytes;
        buffer->used += 2;

        uint32_t_write_big_endian(buffer, content_length, lf_int_bytes);
    }
    else
    {
        der_buf_ensure_capacity(buffer, 2);

        buffer->buf[buffer->used] = type;
        buffer->buf[buffer->used + 1] = (uint8_t)content_length;
        buffer->used += 2;
    }

    return true;
}

der_buffer_t der_tag_header(uint8_t type, uint32_t content_length)
{
    der_buffer_t buffer = {NULL, 0, 0};
    der_write_tag_header(&buffer, type, content_length);    
    return buffer;
}

der_buffer_t der_sequence_tag(uint32_t length)
{
    return der_tag_header(CONSTRUCTED(DER_SEQUENCE), length);
}

void der_write_uint8_t(der_buffer_t *buf, uint8_t x) {
    size_t required_len = x & 0x80 ? 2 : 1;

    der_buffer_t header = der_tag_header(DER_INT, required_len);

    if (!header.buf) {
        return;
    }

    der_buf_write(buf, header.buf, header.used);
    free(header.buf);

    der_buf_ensure_capacity(buf, required_len);
    
    if (x & 0x80) {
        buf->buf[buf->used++] = 0;
    }

    buf->buf[buf->used++] = x;
}