#pragma once

#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include <string>
#include <vector>

namespace asrepl {

/**
 * The core AS/REPL engine; a contained and modern interface on top of Keystone
 * and Capstone for ease-of-use.
 */
class engine {
public:
    /**
     * A processor architecure; Intel or ARM.
     */
    enum class arch {
        intel,
        arm
    };

    /**
     * A processor mode; 32-bit or 64-bit.
     */
    enum class mode {
        b32,
        b64
    };

    engine();

    /**
     * Reconfigure the internal Keystone and Capstone engines; must be called
     * after switching architecture or mode.
     */
    void reconfigure();

    /**
     * Disassemble the given mnemonic(s); will return an empty string on failure.
     */
    std::string assemble(const std::string& input);

    /**
     * Disassemble the given bytes; will return an empty string on failure.
     */
    std::string disassemble(const std::vector<unsigned char>& input) const;

    /**
     * Get the current architecture.
     */
    arch arch() const;

    /**
     * Set the current architecture.
     */
    void set_arch(enum arch arch);

    /**
     * Get the current mode.
     */
    mode mode() const;

    /**
     * Set the current mode.
     */
    void set_mode(enum mode mode);

private:
    enum arch m_arch;
    enum mode m_mode;

    bool m_active;
    ks_engine* m_ks;
    csh m_cs;
};

}
