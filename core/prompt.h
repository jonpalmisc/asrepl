#pragma once

#include "engine.h"

typedef struct {
    asrepl_engine* engine;
} asrepl_prompt;

#ifdef __cplusplus
extern "C" {
#endif

int asrepl_prompt_init(asrepl_prompt* p);
char* asrepl_prompt_send(asrepl_prompt* p, const char* input);

#ifdef __cplusplus
}
#endif
