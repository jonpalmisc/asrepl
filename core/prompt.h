#pragma once

#include "engine.h"
#include <string>

namespace asrepl {

class prompt {
    engine m_engine;
    bool m_exit_requested;

    std::string handle_command(const std::vector<std::string>& args);

public:
    prompt();

    std::string send(const std::string& input);
    bool exit_requested() const;
};

}
