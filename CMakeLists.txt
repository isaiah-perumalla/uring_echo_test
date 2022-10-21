cmake_minimum_required(VERSION 3.23)
project(io_uring_echo_server)

set(CMAKE_CXX_STANDARD 14)

include_directories("/usr/include/liburing")
add_executable(io_uring_echo_server
        echo_server.c)
target_link_libraries(io_uring_echo_server "/usr/lib/liburing.so")
