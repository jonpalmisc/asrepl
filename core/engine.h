#pragma once

#include <capstone/capstone.h>
#include <keystone/keystone.h>

typedef struct {
    ks_engine* keystone;
    csh capstone;
} asrepl_engine;

#ifdef __cplusplus
extern "C" {
#endif

int asrepl_engine_init(asrepl_engine* e);
int asrepl_engine_asm(asrepl_engine* e, const char* input, char** out);
int asrepl_engine_disasm(asrepl_engine* e, const unsigned char* input, size_t length, char** out);

#ifdef __cplusplus
}
#endif
