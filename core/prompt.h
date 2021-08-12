#pragma once

#include "engine.h"
#include <string>

namespace asrepl {

class prompt {
    engine m_engine;

    std::string handle_command(const std::vector<std::string>& args);

public:
    prompt();

    std::string send(const std::string& input);
};

}
