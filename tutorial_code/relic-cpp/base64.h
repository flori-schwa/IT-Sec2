#ifndef BASE64_H
#define BASE64_H

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BASE64_REQUIRED_BLOCKS(len) ((len + 3 - 1) / 3)

#define BASE64_REQUIRED_LENGTH(len) (BASE64_REQUIRED_BLOCKS(len) * 4)

void base64_encode(void* data, size_t len, char* output);

#ifdef __cplusplus
}
#endif

#endif  /* BASE64_H */