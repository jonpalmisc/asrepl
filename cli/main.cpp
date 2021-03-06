#include <iostream>
#include <linenoise.h>
#include <prompt.h>

int main(int argc, char** argv)
{
    asrepl::prompt p;
    std::cout << p.welcome_message() << std::endl;

    char* line;
    while ((line = linenoise("AS/REPL> ")) != nullptr) {
        std::cout << p.send(line) << std::endl;

        if (p.exit_requested())
            break;
    }
}
