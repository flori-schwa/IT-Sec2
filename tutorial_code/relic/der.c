#include "der.h"
#include "od.h"
#include "byteorder.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

/* ============================ UTIL FUNCTIONS ============================ */

int uint32_t_msbyte(uint32_t x) {
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

/* ============================ IMPLEMENTATION ============================ */

void der_buf_init_dynamic(der_buffer_t *buf)
{
    buf->buf = NULL;
    buf->capacity = 0;
    buf->used = 0;
    buf->alloc = dynamic;
}

void der_buf_init(der_buffer_t* buf, uint8_t* memory, size_t alloc, enum alloc_t alloc_type) {
    if (!memory) {
        fprintf(stderr, "Got NULL as stack_memory pointer\n");
        return;
    }

    buf->buf = memory;
    buf->capacity = alloc;
    buf->used = 0;
    buf->alloc = alloc_type;
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
            if (buffer->alloc != dynamic) {
                fprintf(stderr, "Cannot dynamically allocate more memory for der_buffer since it is stack allocated\n");
                return;
            }

            buffer->buf = realloc(buffer->buf, required_total_len);
            buffer->capacity = required_total_len;
        }
    }
}

inline void der_buf_cleanup(der_buffer_t *buffer) {
    free(buffer->buf);
}

void der_buf_write_null_tag(der_buffer_t* buffer) {
    der_buf_ensure_capacity(buffer, DER_BUF_NULL_TAG_SIZE);

    DER_BUF_APPEND_BYTE(buffer, DER_NULL);
    DER_BUF_APPEND_BYTE(buffer, 0);
}

der_buffer_t der_buf_build_sequence(der_buffer_t* body) {
    der_buffer_t head = der_buf_tag_header(CONSTRUCTED(DER_SEQUENCE), body->used);

    size_t total_len = body->used + head.used;

    der_buffer_t final_buf = {
        .buf = malloc(total_len),
        .capacity = total_len,
        .used = 0,
        .alloc = dynamic
    };

    der_buf_write(&final_buf, head.buf, head.used);
    der_buf_write(&final_buf, body->buf, body->used);

    der_buf_cleanup(&head);

    return final_buf;
}

void der_buf_write(der_buffer_t* target, const void* source, uint32_t length) {
    der_buf_ensure_capacity(target, length);
    memcpy((char*) target->buf + target->used, source, (size_t) length);
    target->used += (size_t) length;
}

bool der_buf_write_tag_header(der_buffer_t* buffer, uint8_t type, uint32_t content_length) {
    size_t required_len = der_header_size(content_length);
    der_buf_ensure_capacity(buffer, required_len);

    DER_BUF_APPEND_BYTE(buffer, type);

    if (content_length > 127)
    {
        int lf_int_bytes = uint32_t_msbyte(content_length) + 1;

        DER_BUF_APPEND_BYTE(buffer, 0x80 | lf_int_bytes);
        uint32_t_write_big_endian(buffer, content_length, lf_int_bytes);
    }
    else
    {
        DER_BUF_APPEND_BYTE(buffer, (uint8_t) content_length);
    }

    return true;
}

der_buffer_t der_buf_tag_header(uint8_t type, uint32_t content_length)
{
    der_buffer_t buffer = {NULL, 0, 0, dynamic};
    der_buf_write_tag_header(&buffer, type, content_length);    
    return buffer;
}

der_buffer_t der_buf_sequence_tag(uint32_t length)
{
    return der_buf_tag_header(CONSTRUCTED(DER_SEQUENCE), length);
}

void der_buf_write_uint8_t(der_buffer_t *buf, uint8_t x) {
    size_t value_len = der_uint8_value_len(x);

    if (!der_buf_write_tag_header(buf, DER_INT, value_len)) {
        return;
    }

    der_buf_ensure_capacity(buf, value_len);
    
    if (x & 0x80) {
        DER_BUF_APPEND_BYTE(buf, 0);
    }

    DER_BUF_APPEND_BYTE(buf, x);
}

inline size_t der_header_size(uint32_t content_length) {
    if (content_length <= 127) {
        return 2;
    } else {
        return 2 + (uint32_t_msbyte(content_length) + 1);
    }
}

inline size_t der_sequence_tag_len(uint32_t value_length) {
    return der_header_size(value_length) + value_length;
}

inline size_t der_tag_size(uint32_t value_length) {
    return der_header_size(value_length) + value_length;
}

inline size_t der_uint8_value_len(uint8_t x) {
    return x & 0x80 ? 2 : 1;
}

inline size_t der_uint8_tag_size(uint8_t x) {
    return der_tag_size(der_uint8_value_len(x));
}