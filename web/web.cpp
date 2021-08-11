#include <prompt.h>

#include <emscripten/bind.h>
#include <emscripten/emscripten.h>

static asrepl::prompt g_prompt;

EMSCRIPTEN_KEEPALIVE std::string send(const std::string& input)
{
    return g_prompt.send(input);
}

EMSCRIPTEN_BINDINGS(asrepl_web)
{
    emscripten::function("asreplSend", &send);
}
