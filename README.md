# AS/REPL

> A REPL-style (dis)assembler for the terminal and the web

AS/REPL is a REPL-style interface for assembling and disassembling code. Thanks
to WebAssembly, AS/REPL is available as both a native CLI application as well as
a website.

## Features

AS/REPL is a relatively simple project --- input assembly mnemonics or opcodes,
get back the other.

Currently only (dis)assembling 64-bit x86 code is supported. However, since
AS/REPL uses both [Capstone](https://github.com/aquynh/capstone) and
[Keystone](https://github.com/keystone-engine/keystone) under the hood, adding
support for more architectures should be trivial, and is planned.

## Dependencies

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

## Building

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

# Web Application
emcmake cmake -S . -B build -DASREPL_CLI=OFF -DASREPL_WEB=ON
```

For the latter, you need to have already activated the Emscripten SDK in your
environment so the `emcmake` command is available.

## License

AS/REPL is licensed under the GNU General Public License, Version 3. For more
information, see LICENSE.txt.
