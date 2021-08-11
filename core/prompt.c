#include "prompt.h"
#include "engine.h"
#include "util.h"

int asrepl_prompt_init(asrepl_prompt* p)
{
    p->engine = (asrepl_engine*)malloc(sizeof(asrepl_engine));
    return asrepl_engine_init(p->engine);
}

char* asrepl_prompt_send(asrepl_prompt* p, const char* input)
{
    char* res;
    int err;

    if (is_hex_string(input)) {
        unsigned char* code;
        size_t code_size = hex_decode(input, &code);
        err = asrepl_engine_disasm(p->engine, code, code_size, &res);

        if (err != 0)
            res = "Error: Failed to disassemble";
    } else {
        err = asrepl_engine_asm(p->engine, input, &res);
        if (err != 0)
            res = "Error: Failed to assemble";
    }

    return res;
}
