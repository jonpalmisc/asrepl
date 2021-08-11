#include "prompt.h"

#include "engine.h"
#include "util.h"

#include <string>
#include <vector>

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

    if (util::is_hex_string(input)) {
        auto code = util::hex_decode(input);
        err = asrepl_engine_disasm(m_engine, &code[0], code.size(), &res);
        if (err != 0)
            res = "Error: Failed to disassemble";
    } else {
        err = asrepl_engine_asm(m_engine, input.c_str(), &res);
        if (err != 0)
            res = "Error: Failed to assemble";
    }

    return std::string(res);
}

}
