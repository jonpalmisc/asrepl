#include "util.h"

#include <regex>

namespace asrepl {
namespace util {
    bool is_hex_string(std::string input)
    {
        input.erase(std::remove(input.begin(), input.end(), ' '), input.end());
        return std::regex_match(input, std::regex("^([0-9A-Fa-f]\\s*)+$"));
    }

    std::vector<unsigned char> hex_decode(const std::string& input)
    {
        std::vector<unsigned char> data;
        for (size_t i = 0; i < input.size(); i += 2) {
            std::string byte_string = input.substr(i, 2);
            data.push_back((unsigned char)std::strtol(byte_string.c_str(), NULL, 16));
        }

        return data;
    }
}
}
