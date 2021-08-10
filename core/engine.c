#include "engine.h"

#include <stdio.h>

int asrepl_engine_init(asrepl_engine* e)
{
    ks_engine* ks;

    ks_err err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
    if (err != KS_ERR_OK)
        return 1;

    e->keystone = ks;
    return 0;
}

int asrepl_engine_asm(asrepl_engine* e, const char* input, char** out)
{
    ks_err err;
    size_t count;
    unsigned char* encode;
    size_t size;

    if (ks_asm(e->keystone, input, 0, &encode, &size, &count) != KS_ERR_OK)
        return 1;

    size_t i;
    char* result = calloc(size + 1, sizeof(char));
    for (size_t i = 0; i < size; i++)
        sprintf(&result[i * 2], "%02x", (int)encode[i]);

    ks_free(encode);
    *out = result;
    return 0;
}
