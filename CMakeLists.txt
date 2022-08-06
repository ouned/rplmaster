cmake_minimum_required(VERSION 3.10)

project(rplmaster)

add_compile_definitions(_CRT_SECURE_NO_WARNINGS _WINSOCK_DEPRECATED_NO_WARNINGS)
add_executable(rplmaster master.c master.h lib/ini.c lib/ini.h)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
