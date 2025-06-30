cmake_minimum_required(VERSION 3.10)

project(ServerSSH)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Add executable
add_executable(serverssh serverssh.c)

# Link libraries if needed (for socket programming)
if(UNIX)
    target_link_libraries(serverssh)
endif()

if(WIN32)
    target_link_libraries(serverssh ws2_32)
endif()

# Compiler flags
target_compile_options(serverssh PRIVATE
    $<$<C_COMPILER_ID:GNU>:-Wall -Wextra>
    $<$<C_COMPILER_ID:Clang>:-Wall -Wextra>
    $<$<C_COMPILER_ID:MSVC>:/W4>
)

# Set output directory
set_target_properties(serverssh PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)