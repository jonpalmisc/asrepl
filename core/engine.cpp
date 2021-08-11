#include "engine.h"

#include <sstream>
#include <vector>

namespace asrepl {

engine::engine()
{
    ks_open(KS_ARCH_X86, KS_MODE_64, &m_ks);
    cs_open(CS_ARCH_X86, CS_MODE_64, &m_cs);
}

std::string engine::assemble(const std::string& input)
{
    size_t count, size;
    unsigned char* code;

    if (ks_asm(m_ks, input.c_str(), 0, &code, &size, &count) != KS_ERR_OK)
        return "";

    std::stringstream result;
    for (size_t i = 0; i < size; i++)
        result << std::hex << (int)code[i];

    ks_free(code);
    return result.str();
}

std::string engine::disassemble(const std::vector<unsigned char>& input)
{
    cs_insn* insn;

    size_t count = cs_disasm(m_cs, &input[0], input.size(), 0, 0, &insn);
    if (count > 0) {
        std::stringstream result;
        for (size_t i = 0; i < count; i++)
            result << insn[i].mnemonic << " " << insn[i].op_str << "\n";

        cs_free(insn, count);
        return result.str();
    }

    return "";
}

}
