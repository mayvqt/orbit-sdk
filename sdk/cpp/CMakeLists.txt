cmake_minimum_required(VERSION 3.16)
project(orbit_sdk_cpp VERSION 0.3.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CTest)
option(ORBIT_ENABLE_TLS_TESTS
    "Build the opt-in native transport tests with the Python TLS fixture" OFF)
find_package(Threads REQUIRED)
find_package(CURL 8.0 REQUIRED)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
find_package(jsoncpp 1.9.5 CONFIG QUIET)
if(TARGET JsonCpp::JsonCpp)
    set(ORBIT_JSONCPP_TARGET JsonCpp::JsonCpp)
    set(ORBIT_JSONCPP_USE_CONFIG TRUE)
    set(ORBIT_JSONCPP_PACKAGE jsoncpp)
elseif(TARGET jsoncpp_lib)
    set(ORBIT_JSONCPP_TARGET jsoncpp_lib)
    set(ORBIT_JSONCPP_USE_CONFIG TRUE)
    set(ORBIT_JSONCPP_PACKAGE jsoncpp)
elseif(TARGET jsoncpp_static)
    set(ORBIT_JSONCPP_TARGET jsoncpp_static)
    set(ORBIT_JSONCPP_USE_CONFIG TRUE)
    set(ORBIT_JSONCPP_PACKAGE jsoncpp)
else()
    find_package(JsonCpp 1.9.5 CONFIG QUIET)
    if(TARGET JsonCpp::JsonCpp)
        set(ORBIT_JSONCPP_TARGET JsonCpp::JsonCpp)
        set(ORBIT_JSONCPP_USE_CONFIG TRUE)
        set(ORBIT_JSONCPP_PACKAGE JsonCpp)
    else()
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(JSONCPP REQUIRED IMPORTED_TARGET jsoncpp>=1.9.5)
        set(ORBIT_JSONCPP_TARGET PkgConfig::JSONCPP)
        set(ORBIT_JSONCPP_USE_CONFIG FALSE)
        set(ORBIT_JSONCPP_PACKAGE jsoncpp)
    endif()
endif()

set(ORBIT_SDK_SOURCES
    src/core.cpp
    src/grants.cpp
    src/installed_storage.cpp
    src/json.cpp
    src/persistent_codec.cpp
    src/platform.cpp
    src/persistent_client.cpp
    src/storage.cpp
    src/storage_codec.cpp
    src/storage_linux.cpp
    src/storage_linux_helper.cpp
    src/storage_linux_lease.cpp
    src/storage_linux_installed.cpp
    src/storage_windows.cpp
    src/transport.cpp
)

add_library(orbit_sdk STATIC ${ORBIT_SDK_SOURCES})
add_library(Orbit::Sdk ALIAS orbit_sdk)
target_include_directories(orbit_sdk
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
           $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_compile_features(orbit_sdk PUBLIC cxx_std_17)
set(ORBIT_SDK_LINK_LIBRARIES
    CURL::libcurl OpenSSL::Crypto ${ORBIT_JSONCPP_TARGET} Threads::Threads)
if(WIN32)
    list(APPEND ORBIT_SDK_LINK_LIBRARIES
        ws2_32 bcrypt ntdll userenv advapi32 crypt32 secur32 mincore)
endif()
target_link_libraries(orbit_sdk PUBLIC ${ORBIT_SDK_LINK_LIBRARIES})
set_target_properties(orbit_sdk PROPERTIES EXPORT_NAME Sdk)

if(MSVC)
    target_compile_options(orbit_sdk PRIVATE /W4 /permissive-)
else()
    target_compile_options(orbit_sdk PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(TARGETS orbit_sdk EXPORT OrbitSdkTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(FILES include/orbit_sdk.hpp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/OrbitSdk)
install(EXPORT OrbitSdkTargets NAMESPACE Orbit:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OrbitSdk)

include(CMakePackageConfigHelpers)
configure_package_config_file(cmake/OrbitSdkConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/OrbitSdkConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OrbitSdk
)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/OrbitSdkConfigVersion.cmake
    VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/OrbitSdkConfig.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/OrbitSdkConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OrbitSdk
)

if(BUILD_TESTING AND CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    add_executable(orbit_sdk_tests tests/sdk_test.cpp ${ORBIT_SDK_SOURCES})
    target_include_directories(orbit_sdk_tests PRIVATE include src)
    target_compile_features(orbit_sdk_tests PRIVATE cxx_std_17)
    target_compile_definitions(orbit_sdk_tests PRIVATE ORBIT_SDK_TESTING=1)
    target_link_libraries(orbit_sdk_tests PRIVATE ${ORBIT_SDK_LINK_LIBRARIES})
    target_compile_definitions(orbit_sdk_tests PRIVATE
        ORBIT_GRANT_VECTORS_PATH="${CMAKE_CURRENT_SOURCE_DIR}/../../contracts/sdk/grants.json"
        ORBIT_GRANT_PRIVATE_KEY_PATH="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/es256-test-private.pem"
    )
    if(MSVC)
        target_compile_options(orbit_sdk_tests PRIVATE /W4 /permissive-)
    else()
        target_compile_options(orbit_sdk_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME orbit_sdk_tests COMMAND orbit_sdk_tests)

    add_executable(orbit_platform_tests tests/platform_test.cpp)
    target_include_directories(orbit_platform_tests PRIVATE include src)
    target_compile_features(orbit_platform_tests PRIVATE cxx_std_17)
    target_link_libraries(orbit_platform_tests PRIVATE Orbit::Sdk)
    if(MSVC)
        target_compile_options(orbit_platform_tests PRIVATE /W4 /permissive-)
    else()
        target_compile_options(orbit_platform_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME orbit_platform_tests COMMAND orbit_platform_tests)

    if(ORBIT_ENABLE_TLS_TESTS)
        find_package(Python3 REQUIRED COMPONENTS Interpreter)
        add_executable(orbit_transport_tls_tests tests/transport_tls_driver.cpp ${ORBIT_SDK_SOURCES})
        target_include_directories(orbit_transport_tls_tests PRIVATE include src)
        target_compile_features(orbit_transport_tls_tests PRIVATE cxx_std_17)
        target_compile_definitions(orbit_transport_tls_tests PRIVATE ORBIT_SDK_TESTING=1)
        target_link_libraries(orbit_transport_tls_tests PRIVATE ${ORBIT_SDK_LINK_LIBRARIES})
        if(MSVC)
            target_compile_options(orbit_transport_tls_tests PRIVATE /W4 /permissive-)
        else()
            target_compile_options(orbit_transport_tls_tests PRIVATE -Wall -Wextra -Wpedantic)
        endif()
        add_test(NAME orbit_transport_tls_tests
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/transport_tls_fixture.py
                --driver $<TARGET_FILE:orbit_transport_tls_tests>
                --ca ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/transport-test-ca.pem
                --server-cert ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/transport-test-ip.crt
                --server-key ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/transport-test-ip.key
                --mismatch-cert ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/transport-test-dns.crt
                --mismatch-key ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/transport-test-dns.key)
        set_tests_properties(orbit_transport_tls_tests PROPERTIES TIMEOUT 90 RUN_SERIAL TRUE)
    endif()
endif()
