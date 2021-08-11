#include "prompt.h"

#include "engine.h"
#include "util.h"

#include <string>
#include <vector>

namespace asrepl {

prompt::prompt()
{
}

std::string prompt::send(const std::string& input)
{
    std::string result;

    if (util::is_hex_string(input)) {
        auto code = util::hex_decode(input);
        result = m_engine.disassemble(code);
        if (result.empty())
            result = "Error: Failed to disassemble";
    } else {
        result = m_engine.assemble(input);
        if (result.empty())
            result = "Error: Failed to assemble";
    }

    return result;
}

}
