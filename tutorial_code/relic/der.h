#ifndef DER_H
#define DER_H

#include <stdint.h>
#include <string.h>

#define DER_INT ((uint8_t) 0x02)
#define DER_SEQUENCE ((uint8_t) 0x10)

#define CONSTRUCTED(X) (((uint8_t) 0x20) | X)

typedef struct {
    uint8_t* buf;
    size_t used;
    size_t capacity;
} der_buffer;

void der_buf_init(der_buffer *buf);

void der_buf_ensure_capacity(der_buffer *buffer, size_t offset, size_t length);

der_buffer der_tag_header(uint8_t type, size_t content_length);

der_buffer der_sequence_tag(size_t length);

void der_write_var_int(der_buffer *buf, uint8_t length, uint8_t *int_buf);

#endif /* DER_H */