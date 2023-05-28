cmake_minimum_required(VERSION 3.15 FATAL_ERROR) # NOTE(HK): This is a total guess
project(Medkit)

option(MEDKIT_ASAN              "Medkit: Use AddressSanitizer (if available)"   OFF)
option(MEDKIT_BUILD_EXAMPLES    "Medkit: Build example programs"                ON )

# 
# Meta-project for compile options
# 
add_library(medkit_meta INTERFACE)
if(MSVC)
    target_compile_options(medkit_meta INTERFACE
        /W4
    )
else()
    target_compile_options(medkit_meta INTERFACE
        -Wall -Wextra
    )
endif()
if(MEDKIT_ASAN)
    if(NOT MSVC)
        target_compile_options(medkit_meta INTERFACE -fsanitize=address)
        target_link_libraries(medkit_meta INTERFACE asan)
    endif()
endif()

# 
# Medkit library
# 
add_library(medkit STATIC
    "${CMAKE_CURRENT_LIST_DIR}/medkit.c"
)
target_link_libraries(medkit PRIVATE medkit_meta)

# 
# Example programs
# 
add_executable(medkit-example-cplusplus
    "${CMAKE_CURRENT_LIST_DIR}/examples/cplusplus.cc"
)
target_link_libraries(medkit-example-cplusplus PRIVATE medkit_meta)
add_executable(medkit-example-detours
    "${CMAKE_CURRENT_LIST_DIR}/examples/detours.c"
)
target_link_libraries(medkit-example-detours PRIVATE medkit_meta)
add_executable(medkit-example-dump-executable
    "${CMAKE_CURRENT_LIST_DIR}/examples/dump-executable.c"
)
target_link_libraries(medkit-example-dump-executable PRIVATE medkit_meta)
add_executable(medkit-example-dump-processes
    "${CMAKE_CURRENT_LIST_DIR}/examples/dump-processes.c"
)
target_link_libraries(medkit-example-dump-processes PRIVATE medkit_meta)
