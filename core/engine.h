#pragma once

#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include <string>

namespace asrepl {

class engine {
    ks_engine* m_ks;
    csh m_cs;

public:
    engine();

    std::string assemble(const std::string& input);
    std::string disassemble(const std::vector<unsigned char>& input);
};

}
