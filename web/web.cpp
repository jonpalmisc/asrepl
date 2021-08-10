#include <prompt.h>

#include <emscripten/bind.h>
#include <emscripten/emscripten.h>

#include <string>

static asrepl_prompt* g_prompt;

EMSCRIPTEN_KEEPALIVE void asrepl_web_init()
{
    asrepl_prompt_init(g_prompt);
}

EMSCRIPTEN_KEEPALIVE std::string asrepl_web_send(const std::string& input)
{
    auto* raw_result = asrepl_prompt_send(g_prompt, input.c_str());
    std::string result(raw_result);

    free(raw_result);
    return result;
}

EMSCRIPTEN_BINDINGS(asrepl_web)
{
    emscripten::function("init", &asrepl_web_init);
    emscripten::function("send", &asrepl_web_send);
}
