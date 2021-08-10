#include "prompt.h"
#include "engine.h"

#include <stdlib.h>

int asrepl_prompt_init(asrepl_prompt* p)
{
    p->engine = (asrepl_engine*)malloc(sizeof(asrepl_engine));
    return asrepl_engine_init(p->engine);
}

char* asrepl_prompt_send(asrepl_prompt* p, const char* input)
{
    char* res;
    if (asrepl_engine_asm(p->engine, input, &res) != 0)
        res = "Error: Invalid input";

    return res;
}
