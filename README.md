# AS/REPL

```
AS/REPL> lea rbx, [rsp + 4]
488d5c2404
AS/REPL> 31c0
xor eax, eax
```

> A brief example of what interacting with AS/REPL looks like.

AS/REPL is a REPL-style interface for assembling and disassembling code; input
assembly mnemonics or opcodes, get back the other. Thanks to WebAssembly,
AS/REPL is available as both a native CLI application as well as a website. If
you want, you can [try AS/REPL online](https://asrepl.jonpalmisc.com) right now!

## Supported architectures

At this time, only the following architectures are supported:

- Intel, 32-bit
- Intel, 64-bit
- ARM, 32-bit
- ARM, 64-bit

However, since AS/REPL uses both [Capstone](https://github.com/aquynh/capstone)
and [Keystone](https://github.com/keystone-engine/keystone) under the hood,
adding support for more architectures should be trivial, and is planned.

## Build dependencies

AS/REPL uses the following libraries:

- Keystone, for assembling instructions;
- Capstone, for disassembling instructions;
- linenoise, for the CLI's REPL interface; and
- Emscripten, for targeting WebAssembly.

With the exception of Emscripten, AS/REPL compiles all of its dependencies from
source, so there is no need to install anything via your package manager. While
Emscripten may be available in your package manager, it is recommended to
[install the Emscripten
SDK](https://emscripten.org/docs/getting_started/downloads.html).

## Build instructions

AS/REPL is rather easy to build. All builds will require you to clone the
repository and all of its submodules:

```sh
git clone https://github.com/jonpalmisc/asrepl.git && cd asrepl
git submodule update --init --recursive
```

Next, run CMake either of the following ways depending on the desired target:

```sh
# Native CLI
cmake -S . -B build

# Web application
emcmake cmake -S . -B build -DASREPL_CLI=OFF -DASREPL_WEB=ON
```

For the latter, you need to have already activated the Emscripten SDK in your
environment so the `emcmake` command is available. Starting a web server in the
build directory once AS/REPL is built will allow you to use AS/REPL's web
interface. Easy solutions include `python3 -m http.server` or `php -S
localhost:8000`.

## License and credits

AS/REPL is licensed under the GNU General Public License, Version 3. For more
information, see LICENSE.txt.

This project was inspired by [jsasm](https://jsasm.mmae.kr/), and is not related
to [asrepl](https://github.com/enferex/asrepl), which I discovered after
publishing this project.
