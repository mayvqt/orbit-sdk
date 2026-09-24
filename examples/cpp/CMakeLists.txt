cmake_minimum_required(VERSION 3.16)
project(orbit_cpp_licensed_export LANGUAGES CXX)

set(ORBIT_FFI_STATIC_LIB "" CACHE FILEPATH "Path to the prebuilt Orbit Rust FFI static library")
add_subdirectory(../../sdk/cpp orbit-sdk-build)

add_executable(orbit-cpp-licensed-export main.cpp)
target_link_libraries(orbit-cpp-licensed-export PRIVATE Orbit::Sdk)
