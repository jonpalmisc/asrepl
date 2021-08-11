#pragma once

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

int is_hex_string(const char* raw_input);
size_t hex_decode(const char* raw_input, unsigned char** out);

#ifdef __cplusplus
}
#endif
