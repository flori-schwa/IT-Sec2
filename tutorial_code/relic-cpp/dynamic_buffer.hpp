#ifndef DYNAMIC_BUFFER_H
#define DYNAMIC_BUFFER_H

#include <stdint.h>

class DynamicBuffer {
public: 
    uint8_t* buffer;
    size_t used;
    size_t allocated;

    DynamicBuffer();

    ~DynamicBuffer();

    void ensure_total_capacity(uint32_t required_len);

    void ensure_capacity(uint32_t required_len);

    void append_byte_raw(uint8_t x);

    void write(const void* source, size_t length);
};

#endif /* DYNAMIC_BUFFER_H */