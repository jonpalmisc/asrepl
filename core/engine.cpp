#include "engine.h"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

namespace asrepl {

engine::engine()
    : m_arch(arch::intel)
    , m_mode(mode::b64)
    , m_active(false)
{
    reconfigure();
}

void engine::reconfigure()
{
    ks_arch ks_arch = KS_ARCH_X86;
    int ks_mode = m_mode == mode::b64 ? KS_MODE_64 : KS_MODE_32;
    cs_arch cs_arch = CS_ARCH_X86;
    cs_mode cs_mode = m_mode == mode::b64 ? CS_MODE_64 : CS_MODE_32;

    if (m_arch == arch::arm) {
        ks_arch = m_mode == mode::b64 ? KS_ARCH_ARM64 : KS_ARCH_ARM;
        ks_mode = m_mode == mode::b64 ? KS_MODE_LITTLE_ENDIAN : KS_MODE_ARM;
        cs_arch = m_mode == mode::b64 ? CS_ARCH_ARM64 : CS_ARCH_ARM;
        cs_mode = CS_MODE_ARM;
    }

    if (m_active) {
        ks_close(m_ks);
        cs_close(&m_cs);
    }

    if (ks_err ke = ks_open(ks_arch, ks_mode, &m_ks); ke != KS_ERR_OK)
        std::cout << "Failed to load Keystone; this is a bug, crashes are imminent (" << (int)ke << ")\n";
    if (cs_err ce = cs_open(cs_arch, cs_mode, &m_cs); ce != CS_ERR_OK)
        std::cout << "Failed to load Capstone; this is a bug, crashes are imminent (" << (int)ce << ")\n";

    m_active = true;
}

std::string engine::assemble(const std::string& input)
{
    size_t count, size;
    unsigned char* code;

    if (ks_asm(m_ks, input.c_str(), 0, &code, &size, &count) != KS_ERR_OK) {
        auto* error_desc = ks_strerror(ks_errno(m_ks));
        return "Error: " + std::string(error_desc);
    }

    std::stringstream result;
    for (size_t i = 0; i < size; i++)
        result << std::hex << std::setw(2) << std::setfill('0') << (int)code[i];

    ks_free(code);
    return result.str();
}

std::string engine::disassemble(const std::vector<unsigned char>& input) const
{
    cs_insn* insn;

    size_t count = cs_disasm(m_cs, &input[0], input.size(), 0, 0, &insn);
    if (count > 0) {
        std::stringstream result;
        for (size_t i = 0; i < count; i++) {
            result << insn[i].mnemonic << " " << insn[i].op_str;
            if (i != count - 1)
                result << "\n";
        }

        cs_free(insn, count);
        return result.str();
    }

    return "Error: No instructions found";
}

enum engine::arch engine::arch() const
{
    return m_arch;
}

void engine::set_arch(enum arch a)
{
    m_arch = a;
}

enum engine::mode engine::mode() const
{
    return m_mode;
}

void engine::set_mode(enum mode m)
{
    m_mode = m;
}

}
