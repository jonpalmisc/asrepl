#pragma once

#include <string>
#include <vector>

namespace asrepl::util {

bool is_hex_string(std::string input);
bool is_command_string(std::string input);
std::vector<std::string> tokenize(const std::string& input);
std::vector<unsigned char> hex_decode(const std::string& input);

}
