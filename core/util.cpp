#include "util.h"

#include <regex>
#include <string>

extern "C" int is_hex_string(const char* raw_input)
{
    std::string input(raw_input);
    input.erase(std::remove(input.begin(), input.end(), ' '), input.end());

    return std::regex_match(input, std::regex("^([0-9A-Fa-f]\\s*)+$"));
}

extern "C" size_t hex_decode(const char* raw_input, unsigned char** out)
{
    std::string input(raw_input);
    std::vector<unsigned char> data;

    for (size_t i = 0; i < input.size(); i += 2) {
        std::string byte_string = input.substr(i, 2);
        data.push_back((unsigned char)std::strtol(byte_string.c_str(), NULL, 16));
    }

    unsigned char* raw_data = new unsigned char[data.size()];
    for (size_t i = 0; i < data.size(); i++)
        raw_data[i] = data[i];

    *out = raw_data;
    return data.size();
}
