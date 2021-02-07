#ifndef DER_HPP
#define DER_HPP

#include "dynamic_buffer.hpp"

#include <stdint.h>

#define DER_INT ((uint8_t) 0x02)
#define DER_BIT_STRING ((uint8_t) 0x03)
#define DER_NULL ((uint8_t) 0x05)
#define DER_OBJECT_ID ((uint8_t) 0x06)
#define DER_SEQUENCE ((uint8_t) 0x10)

#define CONSTRUCTED(X) (((uint8_t) 0x20) | X)

#define DER_BUF_NULL_TAG_SIZE (2)

#define NTH_BYTE(x, n) ((x & (0xFF << (n * 8))) >> (n * 8))

int uint32_t_msbyte(uint32_t x);

class DerBuffer : public DynamicBuffer {
public:

    void write_null_tag();

    void write_tag_header(uint8_t type, uint32_t content_length);

    void write_uint8(uint8_t x);

    void uint32_t_write_big_endian(uint32_t x, int max);

    static size_t header_size(uint32_t content_length);

    static size_t tag_size(uint32_t value_length);

    static size_t uint8_value_len(uint8_t x);

};

#endif /* DER_HPP */