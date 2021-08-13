#pragma once

#include "engine.h"
#include <string>

namespace asrepl {

/**
 * A basic, generic prompt interface for use from the CLI or web app.
 */
class prompt {
    engine m_engine;
    bool m_exit_requested;

    /**
     * Handle an internal "slash command".
     */
    std::string handle_command(const std::vector<std::string>& args);

    /**
     * Get the current architecture and mode string.
     */
    std::string info_string() const;

public:
    prompt();

    /**
     * Get the startup/welcome message.
     */
    std::string welcome_message() const;

    /**
     * Send input to the prompt. Can be internal commands, mnemonics, or opcodes.
     */
    std::string send(const std::string& input);

    /**
     * Was an exit requested?
     */
    bool exit_requested() const;
};

}
