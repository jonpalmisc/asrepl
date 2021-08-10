#pragma once

#include <keystone/keystone.h>

typedef struct {
    ks_engine* keystone;
} asrepl_engine;

int asrepl_engine_init(asrepl_engine* e);
int asrepl_engine_asm(asrepl_engine* e, const char* input, char** out);
