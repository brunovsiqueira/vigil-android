cmake_minimum_required(VERSION 3.22.1)
project("vigil_native")

add_library(vigil_native SHARED
    art_method_check.c
    proc_reader.c
)

target_link_libraries(vigil_native
    log
)
