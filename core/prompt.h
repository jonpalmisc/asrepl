#pragma once

#include "engine.h"
#include <string>

namespace asrepl {

class prompt {
    engine m_engine;
    bool m_exit_requested;

    std::string handle_command(const std::vector<std::string>& args);
    std::string info_string() const;

public:
    prompt();

    /**
     * Get the startup/welcome message.
     */
    std::string welcome_message() const;

    std::string send(const std::string& input);
    bool exit_requested() const;
};

}
