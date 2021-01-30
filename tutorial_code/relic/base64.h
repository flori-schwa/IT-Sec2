#ifndef BASE64_H
#define BASE64_H

#include <stdlib.h>

#define BASE64_REQUIRED_BLOCKS(len) ((len + 3 - 1) / 3)

#define BASE64_REQUIRED_LENGTH(len) (BASE64_REQUIRED_BLOCKS(len) * 4)

void base64_encode(void* data, size_t len, char* output);

#endif  /* BASE64_H */