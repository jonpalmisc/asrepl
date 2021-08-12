#include <iostream>
#include <linenoise.h>
#include <prompt.h>

int main(int argc, char** argv)
{
    asrepl::prompt p;

    char* line;
    while ((line = linenoise("as> ")) != NULL)
        std::cout << p.send(line) << std::endl;
}