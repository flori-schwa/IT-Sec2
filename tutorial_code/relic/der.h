#ifndef DER_H
#define DER_H

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#define DER_INT ((uint8_t) 0x02)
#define DER_BIT_STRING ((uint8_t) 0x03)
#define DER_NULL ((uint8_t) 0x05)
#define DER_OBJECT_ID ((uint8_t) 0x06)
#define DER_SEQUENCE ((uint8_t) 0x10)

#define CONSTRUCTED(X) (((uint8_t) 0x20) | X)

#define DER_BUF_NULL_TAG_SIZE (2)

#define DER_BUF_APPEND_BYTE(buffer, value) (buffer)->buf[(buffer)->used++] = value

typedef struct {
    uint8_t* buf;
    size_t used;
    size_t capacity;

    enum alloc_t {
        dynamic,
        stack
    } alloc;
} der_buffer_t;

void der_buf_init_dynamic(der_buffer_t *buf);

void der_buf_init(der_buffer_t* buf, uint8_t* memory, size_t alloc, enum alloc_t alloc_type);

void der_buf_ensure_capacity(der_buffer_t *buffer, uint32_t length);

void der_buf_cleanup(der_buffer_t *buffer);

void der_buf_write(der_buffer_t* target, const void* source, uint32_t length);

void der_buf_write_null_tag(der_buffer_t* buffer);

bool der_buf_write_tag_header(der_buffer_t* buffer, uint8_t type, uint32_t content_length);

der_buffer_t der_buf_tag_header(uint8_t type, uint32_t content_length);

der_buffer_t der_buf_build_sequence(der_buffer_t* body);

der_buffer_t der_buf_sequence_tag(uint32_t length);

void der_buf_write_uint8_t(der_buffer_t *buf, uint8_t x);

int uint32_t_msbyte(uint32_t x);

size_t der_header_size(uint32_t content_length);

size_t der_sequence_tag_len(uint32_t value_length);

size_t der_tag_size(uint32_t value_length);

size_t der_uint8_value_len(uint8_t x);

size_t der_uint8_tag_size(uint8_t x);

#endif /* DER_H */