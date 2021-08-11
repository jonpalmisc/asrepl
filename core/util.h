#pragma once

#include <string>

namespace asrepl {
namespace util {
    bool is_hex_string(std::string input);
    std::vector<unsigned char> hex_decode(const std::string& input);
}
}
