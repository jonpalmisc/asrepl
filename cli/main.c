#include <prompt.h>

#include <stddef.h>
#include <stdio.h>

#include <linenoise.h>

int main(int argc, char** argv)
{
    asrepl_prompt p;
    asrepl_prompt_init(&p);

    char* line;
    while ((line = linenoise("as> ")) != NULL) {
        char* result = asrepl_prompt_send(&p, line);
        printf("  %s\n", result);
    }
}
