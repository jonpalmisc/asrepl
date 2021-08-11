#include "prompt.h"

#include "engine.h"
#include "util.h"
#include <string>

namespace asrepl {

prompt::prompt()
{
    m_engine = new asrepl_engine;
    asrepl_engine_init(m_engine);
}

std::string prompt::send(const std::string& input)
{
    char* res;
    int err;

    if (is_hex_string(input.c_str())) {
        unsigned char* code;
        size_t code_size = hex_decode(input.c_str(), &code);
        err = asrepl_engine_disasm(m_engine, code, code_size, &res);

        if (err != 0)
            res = "Error: Failed to disassemble";
    } else {
        err = asrepl_engine_asm(m_engine, input.c_str(), &res);
        // if (err != 0)
        //     res = "Error: Failed to assemble";
    }

    auto sres = std::string(res);

    return sres;
}

}
