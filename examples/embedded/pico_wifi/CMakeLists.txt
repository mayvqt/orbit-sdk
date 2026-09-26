cmake_minimum_required(VERSION 3.16)
include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)
project(orbit_pico_wifi C CXX ASM)
set(PICO_MBEDTLS_CONFIG_FILE "${CMAKE_CURRENT_LIST_DIR}/mbedtls_config.h")
pico_sdk_init()
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ORBIT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../sdk/embedded)
add_subdirectory(${ORBIT_DIR} orbit)
add_executable(orbit_pico_wifi main.c ../common/client.c
    ${ORBIT_DIR}/adapters/pico.c ${ORBIT_DIR}/adapters/mbedtls.c)
target_include_directories(orbit_pico_wifi PRIVATE . ../common)
target_link_libraries(orbit_pico_wifi PRIVATE orbit_embedded_transport
    pico_stdlib pico_flash pico_cyw43_arch_lwip_poll pico_lwip_mbedtls
    pico_mbedtls_headers pico_mbedtls_crypto pico_mbedtls_x509 pico_mbedtls_tls)
target_compile_definitions(orbit_pico_wifi PRIVATE ALTCP_MBEDTLS_AUTHMODE=MBEDTLS_SSL_VERIFY_REQUIRED)
pico_add_extra_outputs(orbit_pico_wifi)
