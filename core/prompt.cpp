#include "prompt.h"

#include "engine.h"
#include "util.h"

#include <string>
#include <vector>

namespace asrepl {

prompt::prompt()
    : m_exit_requested(false)
{
}

constexpr auto k_command_mode = "/mode";
constexpr auto k_command_arch = "/arch";
constexpr auto k_command_info = "/info";
constexpr auto k_command_help = "/help";
constexpr auto k_command_exit = "/exit";
constexpr auto k_command_quit = "/quit";

std::string prompt::handle_command(const std::vector<std::string>& args)
{
    if (args.empty())
        return "Error: Invalid arguments";

    auto command = args[0];

    if (command == k_command_help)
        return "Help is currently unavailable";

    if (command == k_command_exit || command == k_command_quit) {
        m_exit_requested = true;
        return "";
    }

    if (command == k_command_info) {
        std::string arch = m_engine.arch() == engine::arch::intel ? "Intel" : "ARM";
        std::string mode = m_engine.mode() == engine::mode::b64 ? "64-bit" : "32-bit";

        return "Architecture is " + arch + ", " + mode;
    }

    if (command == k_command_arch) {
        if (args.size() < 2)
            return "Usage: /arch {intel,arm}";

        auto arch = args[1];
        if (arch != "intel" && arch != "arm")
            return "Error: Unrecognized mode; expected 'intel' or 'arm'";

        m_engine.set_arch(arch == "arm" ? engine::arch::arm : engine::arch::intel);
        m_engine.restart();
    }

    if (command == k_command_mode) {
        if (args.size() < 2)
            return "Usage: /mode {32,64}";

        auto mode = args[1];
        if (mode != "32" && mode != "64")
            return "Error: Unrecognized mode; expected '32' or '64'";

        m_engine.set_mode(mode == "32" ? engine::mode::b32 : engine::mode::b64);
        m_engine.restart();
    }

    return "Error: Unknown command, see /help for more info";
}

std::string prompt::send(const std::string& input)
{
    std::string result;

    if (util::is_command_string(input))
        return handle_command(util::tokenize(input));

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

bool prompt::exit_requested() const
{
    return m_exit_requested;
}

}
