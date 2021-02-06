#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "der.hpp"

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

/* ============================ IMPLEMENTATION ============================ */

DerBuffer::DerBuffer()
{
    this->buf = nullptr;
    this->allocated = 0;
    this->used = 0;
}

DerBuffer::~DerBuffer()
{
    this->cleanup();
}

void DerBuffer::cleanup()
{
    free(this->buf);
}

void DerBuffer::ensure_capacity(uint32_t requiredLen)
{
    uint32_t offset = this->used;
    size_t required_total_len = (size_t) (offset + requiredLen);

    if (!this->buf) {
        this->buf = (uint8_t*) malloc(required_total_len);
        this->allocated = required_total_len;
    }
    else {
        if (this->allocated < required_total_len) {
            this->buf = (uint8_t*) realloc(this->buf, required_total_len);
            this->allocated = required_total_len;
        }
    }
}

void DerBuffer::write(const void *source, uint32_t content_length)
{
    this->ensure_capacity(content_length);
    memcpy(this->buf + this->used, source, (size_t) content_length);
    this->used += content_length;
}

void DerBuffer::append_raw(uint8_t x) {
    this->buf[this->used++] = x;
}

void DerBuffer::write_null_tag()
{
    this->ensure_capacity(DER_BUF_NULL_TAG_SIZE);

    this->append_raw(DER_NULL);
    this->append_raw(0);
}

void DerBuffer::write_tag_header(uint8_t type, uint32_t content_length)
{
    size_t required_len = header_size(content_length);
    this->ensure_capacity(required_len);

    this->append_raw(type);

    if (content_length > 127) {
        int lf_int_bytes = uint32_t_msbyte(content_length) + 1;

        this->append_raw(0x80 | lf_int_bytes);
        this->uint32_t_write_big_endian(content_length, lf_int_bytes);
    } else {
        this->append_raw((uint8_t) content_length);
    }
}

void DerBuffer::write_uint8(uint8_t x)
{
    size_t value_len = uint8_value_len(x);

    this->write_tag_header(DER_INT, value_len);

    this->ensure_capacity(value_len);

    if (x & 0x80) {
        this->append_raw(0);
    }

    this->append_raw(x);
}

void DerBuffer::uint32_t_write_big_endian(uint32_t x, int max) {
    if (max <= 0 || (size_t) max >= sizeof(uint32_t)) {
        return;
    }

    this->ensure_capacity(max);

    for (int byte = max - 1; byte >= 0; byte--) {
        this->append_raw(NTH_BYTE(x, byte));
    }
}

size_t DerBuffer::header_size(uint32_t content_length)
{
    if (content_length <= 127) {
        return 2;
    } else {
        return 2 + (uint32_t_msbyte(content_length) + 1);
    }
}

size_t DerBuffer::tag_size(uint32_t value_length)
{
    return header_size(value_length) + value_length;
}

size_t DerBuffer::uint8_value_len(uint8_t x)
{
    return x & 0x80 ? 2 : 1;
}
