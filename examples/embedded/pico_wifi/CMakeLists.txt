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
if(DEFINED ENV{ORBIT_APP_KEY})
    target_compile_definitions(orbit_pico_wifi PRIVATE ORBIT_APP_KEY=\"$ENV{ORBIT_APP_KEY}\")
endif()
pico_add_extra_outputs(orbit_pico_wifi)
# Compile and link agree on the physical flash and the explicit two-slot reserve.
if(PICO_BOARD STREQUAL "pico2_w")
 set(ORBIT_PICO_FLASH_BYTES 4194304)
else()
 set(ORBIT_PICO_FLASH_BYTES 2097152)
endif()
set(ORBIT_PICO_SLOT_BYTES 4096)
if(ORBIT_ENABLE_OFFLINE)
 math(EXPR ORBIT_PICO_SLOT_BYTES "((64 + 1024 + ${ORBIT_OFFLINE_PROFILE_FILE_BYTES} + 4095) / 4096) * 4096")
endif()
math(EXPR ORBIT_FIRMWARE_FLASH_LIMIT "0x10000000 + ${ORBIT_PICO_FLASH_BYTES} - 2 * ${ORBIT_PICO_SLOT_BYTES}")
target_compile_definitions(orbit_pico_wifi PRIVATE ORBIT_PICO_FLASH_BYTES=${ORBIT_PICO_FLASH_BYTES})
target_link_options(orbit_pico_wifi PRIVATE
 -Wl,--defsym=ORBIT_FIRMWARE_FLASH_LIMIT=${ORBIT_FIRMWARE_FLASH_LIMIT}
 -Wl,-T,${CMAKE_CURRENT_LIST_DIR}/orbit_journal_reserve.ld)
