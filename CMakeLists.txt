cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(asrepl C CXX)

# Options to enable/disable building the CLI and web interface
option(ASREPL_CLI ON)
option(ASREPL_WEB OFF)

# Build Keystone for x86, ensure it is linked statically.
set(BUILD_SHARED_LIBS OFF)
set(LLVM_TARGETS_TO_BUILD "X86")
add_subdirectory(vendor/keystone)
target_include_directories(keystone PUBLIC vendor/keystone/include)

# Build Capstone for x86
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF)
set(CAPSTONE_X86_SUPPORT ON)
set(CAPSTONE_BUILD_DIET ON)
set(CAPSTONE_X86_REDUCE ON)
set(CAPSTONE_X86_ATT_DISABLE ON)
set(CAPSTONE_BUILD_STATIC ON)
set(CAPSTONE_BUILD_SHARED OFF)
set(CAPSTONE_BUILD_TESTS OFF)
set(CAPSTONE_BUILD_CSTOOL OFF)
add_subdirectory(vendor/capstone)
target_include_directories(capstone-static PUBLIC vendor/capstone/include)

set(CORE_SRC
  ${CMAKE_SOURCE_DIR}/core/engine.cpp
  ${CMAKE_SOURCE_DIR}/core/engine.h
  ${CMAKE_SOURCE_DIR}/core/prompt.cpp
  ${CMAKE_SOURCE_DIR}/core/prompt.h
  ${CMAKE_SOURCE_DIR}/core/util.cpp
  ${CMAKE_SOURCE_DIR}/core/util.h)

# Build the core, statically linking-in Keystone
add_library(asrepl-core ${CORE_SRC})
target_include_directories(asrepl-core PUBLIC core)
target_compile_features(asrepl-core PUBLIC cxx_std_17)
target_link_libraries(asrepl-core PUBLIC keystone capstone-static)

if(ASREPL_CLI)
  set(CLI_SRC ${CMAKE_SOURCE_DIR}/cli/main.cpp)

  # Build linenoise as a static library
  add_library(linenoise
    vendor/linenoise/linenoise.c
    vendor/linenoise/linenoise.h)
  target_include_directories(linenoise PUBLIC vendor/linenoise)

  # Build the CLI & link with linenoise
  add_executable(asrepl-cli ${CLI_SRC})
  target_link_libraries(asrepl-cli asrepl-core linenoise)
endif()

if(ASREPL_WEB)
  set(WEB_SRC ${CMAKE_SOURCE_DIR}/web/web.cpp)

  # Build the web WASM wrapper
  add_executable(asrepl-web ${WEB_SRC})
  target_link_libraries(asrepl-web asrepl-core)
  target_link_options(asrepl-web PRIVATE --bind)

  # Copy web assets to the build folder
  add_custom_target(asrepl-web-copy ALL
    COMMAND ${CMAKE_COMMAND} -E copy
    ${CMAKE_SOURCE_DIR}/web/index.html
    ${CMAKE_SOURCE_DIR}/web/asrepl.css
    ${CMAKE_BINARY_DIR})
  add_dependencies(asrepl-web asrepl-web-copy)
endif()

# Nice to have
add_custom_target(format
  COMMAND clang-format -i --style=WebKit ${CORE_SRC} ${CLI_SRC} ${WEB_SRC})
