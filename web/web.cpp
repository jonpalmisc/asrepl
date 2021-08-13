#include <prompt.h>

#include <emscripten/bind.h>
#include <emscripten/emscripten.h>

#include <iostream>

asrepl::prompt* g_prompt = nullptr;

EMSCRIPTEN_KEEPALIVE void init()
{
    std::cout << "Initializing prompt... ";
    g_prompt = new asrepl::prompt;
    std::cout << "Done." << std::endl;
}

EMSCRIPTEN_KEEPALIVE std::string welcome_message()
{
    return g_prompt->welcome_message();
}

EMSCRIPTEN_KEEPALIVE std::string send(const std::string& input)
{
    return g_prompt->send(input);
}


EMSCRIPTEN_BINDINGS(asrepl_web)
{
    emscripten::function("asreplInit", &init);
    emscripten::function("asreplWelcome", &welcome_message);
    emscripten::function("asreplSend", &send);
}

int main() {
    std::cout << "AS/REPL WebAssembly module loaded." << std::endl;
}
