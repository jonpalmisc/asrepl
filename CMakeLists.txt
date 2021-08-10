cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(asrepl C CXX)

option(ASREPL_CLI ON)
option(ASREPL_WEB OFF)

set(BUILD_SHARED_LIBS OFF)
set(LLVM_TARGETS_TO_BUILD "AArch64;X86")
add_subdirectory(vendor/keystone)
target_include_directories(keystone PUBLIC vendor/keystone/include)

set(CORE_SRC
  ${CMAKE_SOURCE_DIR}/core/engine.c
  ${CMAKE_SOURCE_DIR}/core/engine.h
  ${CMAKE_SOURCE_DIR}/core/prompt.c
  ${CMAKE_SOURCE_DIR}/core/prompt.h)

add_library(asrepl-core ${CORE_SRC})
target_include_directories(asrepl-core PUBLIC core)
target_link_libraries(asrepl-core PUBLIC keystone)

if(ASREPL_CLI)
  add_library(linenoise
    vendor/linenoise/linenoise.c
    vendor/linenoise/linenoise.h)
  target_include_directories(linenoise PUBLIC vendor/linenoise)

  set(CLI_SRC ${CMAKE_SOURCE_DIR}/cli/main.c)
  add_executable(asrepl-cli ${CLI_SRC})
  target_link_libraries(asrepl-cli asrepl-core linenoise)
endif()

if(ASREPL_WEB)
  set(WEB_SRC ${CMAKE_SOURCE_DIR}/web/web.cpp)
  add_executable(asrepl-web ${WEB_SRC})
  target_link_libraries(asrepl-web asrepl-core)
  target_link_options(asrepl-web PRIVATE --bind)

  # Copy the index.html on build
  add_custom_target(asrepl-web-copy ALL
    COMMAND ${CMAKE_COMMAND} -E copy
    ${CMAKE_SOURCE_DIR}/web/index.html
    ${CMAKE_SOURCE_DIR}/web/asrepl.css
    ${CMAKE_BINARY_DIR})
  add_dependencies(asrepl-web asrepl-web-copy)
endif()

add_custom_target(clang_format
  COMMAND clang-format -i --style=WebKit ${CORE_SRC} ${CLI_SRC} ${WEB_SRC})
