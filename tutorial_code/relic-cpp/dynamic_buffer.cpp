#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "dynamic_buffer.hpp"

DynamicBuffer::DynamicBuffer()
{
    this->buffer = nullptr;
    this->used = 0;
    this->allocated = 0;
}

DynamicBuffer::~DynamicBuffer()
{
    free(this->buffer);
}

void DynamicBuffer::ensure_total_capacity(uint32_t required_len)
{
    this->ensure_capacity(required_len - this->used);
}

void DynamicBuffer::ensure_capacity(uint32_t required_len)
{
    uint32_t offset = this->used;
    size_t required_total_len = (size_t) (offset + required_len);

    if (!this->buffer) {
        this->buffer = (uint8_t*) malloc(required_total_len);
        this->allocated = required_total_len;
    }
    else {
        if (this->allocated < required_total_len) {
            this->buffer = (uint8_t*) realloc(this->buffer, required_total_len);
            this->allocated = required_total_len;
        }
    }
}

void DynamicBuffer::append_byte_raw(uint8_t x)
{
    this->buffer[this->used++] = x;
}

void DynamicBuffer::write(const void *source, size_t length)
{
    this->ensure_capacity(length);
    memcpy(this->buffer + this->used, source, length);
    this->used += length;
}