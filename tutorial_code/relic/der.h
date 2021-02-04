#ifndef DER_H
#define DER_H

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define DER_INT ((uint8_t) 0x02)
#define DER_BIT_STRING ((uint8_t) 0x03)
#define DER_NULL ((uint8_t) 0x05)
#define DER_OBJECT_ID ((uint8_t) 0x06)
#define DER_SEQUENCE ((uint8_t) 0x10)

#define CONSTRUCTED(X) (((uint8_t) 0x20) | X)

typedef struct {
    uint8_t* buf;
    size_t used;
    size_t capacity;
} der_buffer_t;

void der_write_null_tag(der_buffer_t* buffer);

void der_write_rsa_oid(der_buffer_t* buffer);

der_buffer_t der_buf_build_sequence(der_buffer_t* body);

void der_buf_init(der_buffer_t *buf);

void der_buf_ensure_capacity(der_buffer_t *buffer, uint32_t length);

void der_buf_write(der_buffer_t* target, void* source, uint32_t length);

bool der_write_tag_header(der_buffer_t* buffer, uint8_t type, uint32_t content_length);

der_buffer_t der_tag_header(uint8_t type, uint32_t content_length);

der_buffer_t der_sequence_tag(uint32_t length);

void der_write_uint8_t(der_buffer_t *buf, uint8_t x);

#endif /* DER_H */