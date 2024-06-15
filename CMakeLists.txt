cmake_minimum_required(VERSION 3.28)
project(mc_unlocker C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_EXE_LINKER_FLAGS "-static")

add_executable(mc_unlocker main.c)

target_link_libraries(mc_unlocker version)
