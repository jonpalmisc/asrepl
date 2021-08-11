#include "engine.h"

#include <stdio.h>

int asrepl_engine_init(asrepl_engine* e)
{
    ks_engine* ks;

    ks_err err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
    if (err != KS_ERR_OK)
        return 1;
    e->keystone = ks;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &e->capstone) != CS_ERR_OK)
        return 1;

    return 0;
}

int asrepl_engine_asm(asrepl_engine* e, const char* input, char** out)
{
    size_t count;
    unsigned char* code;
    size_t size;

    if (ks_asm(e->keystone, input, 0, &code, &size, &count) != KS_ERR_OK)
        return 1;

    char* result = calloc(size + 1, sizeof(char));
    for (size_t i = 0; i < size; i++)
        sprintf(&result[i * 2], "%02x", (int)code[i]);

    ks_free(code);
    *out = result;
    return 0;
}

int asrepl_engine_disasm(asrepl_engine* e, const unsigned char* input, size_t length, char** out)
{
    cs_insn* insn;

    size_t count = cs_disasm(e->capstone, input, length, 0x1000, 0, &insn);
    if (count > 0) {
        char* result = malloc(sizeof(char) * 192 * count);

        char* r = result;
        for (size_t i = 0; i < count; i++)
            r += sprintf(r, "%s %s\n", insn[i].mnemonic, insn[i].op_str);

        *out = result;
        cs_free(insn, count);
    } else {
        return 1;
    }

    return 0;
}
