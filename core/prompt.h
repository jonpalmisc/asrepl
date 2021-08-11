#pragma once

#include "engine.h"
#include <string>

namespace asrepl {

class prompt {
    asrepl_engine* m_engine;

public:
    prompt();

    std::string send(const std::string& input);
};

}
