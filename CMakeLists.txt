cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(asrepl C)

set(BUILD_SHARED_LIBS ON)
set(LLVM_TARGETS_TO_BUILD "AArch64;X86")
add_subdirectory(vendor/keystone)
target_include_directories(keystone PUBLIC vendor/keystone/include)

add_library(linenoise
  vendor/linenoise/linenoise.c
  vendor/linenoise/linenoise.h)
target_include_directories(linenoise PUBLIC vendor/linenoise)

set(CORE_SRC
  ${CMAKE_SOURCE_DIR}/core/engine.c
  ${CMAKE_SOURCE_DIR}/core/engine.h
  ${CMAKE_SOURCE_DIR}/core/prompt.c
  ${CMAKE_SOURCE_DIR}/core/prompt.h)

add_library(asrepl-core ${CORE_SRC})
target_include_directories(asrepl-core PUBLIC core)
target_link_libraries(asrepl-core PUBLIC keystone)

set(CLI_SRC ${CMAKE_SOURCE_DIR}/cli/main.c)

add_executable(asrepl-cli ${CLI_SRC})
target_link_libraries(asrepl-cli asrepl-core linenoise)

add_custom_target(clang_format COMMAND clang-format -i --style=WebKit ${CORE_SRC} ${CLI_SRC})
