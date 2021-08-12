#pragma once

#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include <string>

namespace asrepl {

class engine {
public:
    enum class arch {
        intel,
        arm
    };

    enum class mode {
        b32,
        b64
    };

    engine();

    void restart();
    std::string assemble(const std::string& input);
    std::string disassemble(const std::vector<unsigned char>& input) const;

    arch arch() const;
    void set_arch(enum arch arch);

    mode mode() const;
    void set_mode(enum mode mode);

private:
    enum arch m_arch;
    enum mode m_mode;

    bool m_active;
    ks_engine* m_ks;
    csh m_cs;
};

}
