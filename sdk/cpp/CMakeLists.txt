cmake_minimum_required(VERSION 3.16)
project(orbit_sdk_cpp LANGUAGES CXX)

set(ORBIT_FFI_STATIC_LIB "" CACHE FILEPATH "Path to the prebuilt Orbit Rust FFI static library")
if(NOT ORBIT_FFI_STATIC_LIB OR NOT EXISTS "${ORBIT_FFI_STATIC_LIB}")
    message(FATAL_ERROR "Set ORBIT_FFI_STATIC_LIB to the prebuilt orbit-sdk-ffi static library")
endif()

find_package(Threads REQUIRED)

add_library(orbit_sdk STATIC src/orbit_sdk.cpp)
add_library(Orbit::Sdk ALIAS orbit_sdk)
target_include_directories(orbit_sdk PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_features(orbit_sdk PUBLIC cxx_std_17)
target_link_libraries(orbit_sdk PUBLIC "${ORBIT_FFI_STATIC_LIB}" Threads::Threads)

if(WIN32)
    target_link_libraries(orbit_sdk PUBLIC ws2_32 bcrypt ntdll userenv advapi32 crypt32 secur32)
elseif(UNIX AND NOT APPLE)
    target_link_libraries(orbit_sdk PUBLIC dl m rt)
endif()
