cmake_minimum_required(VERSION 3.20)
project(orbit_stm32g0b1re_link_check C ASM)
add_compile_options(-mcpu=cortex-m0plus -mthumb -Os -ffunction-sections
                    -fdata-sections -fno-common)

set(STM32CUBE_G0_PATH "" CACHE PATH "STM32CubeG0 1.6.3 checkout")
set(MBEDTLS_PATH "" CACHE PATH "Mbed TLS 3.6.6 checkout")
set(ORBIT_APP_KEY "" CACHE STRING "Synthetic/public Orbit app key used at build time")
set(ORBIT_CLIENT_ARENA_BYTES 32768 CACHE STRING "Orbit arena size: 8192..32768 bytes")
if(NOT STM32CUBE_G0_PATH OR NOT MBEDTLS_PATH OR NOT ORBIT_APP_KEY)
    message(FATAL_ERROR "Set STM32CUBE_G0_PATH, MBEDTLS_PATH, and ORBIT_APP_KEY")
endif()
if(ORBIT_CLIENT_ARENA_BYTES LESS 8192 OR ORBIT_CLIENT_ARENA_BYTES GREATER 32768)
    message(FATAL_ERROR "ORBIT_CLIENT_ARENA_BYTES must be between 8192 and 32768")
endif()

set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ORBIT_BUILD_POSIX OFF CACHE BOOL "" FORCE)
set(ORBIT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../../sdk/embedded)
add_subdirectory(${ORBIT_DIR} orbit)

set(MBEDTLS_CONFIG_FILE ${CMAKE_CURRENT_LIST_DIR}/mbedtls_config.h CACHE FILEPATH "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
add_subdirectory(${MBEDTLS_PATH} mbedtls)

set(CUBE_DRIVERS ${STM32CUBE_G0_PATH}/Drivers)
set(CUBE_PROJECT ${STM32CUBE_G0_PATH}/Projects/NUCLEO-G0B1RE/Templates)
set(HAL ${CUBE_DRIVERS}/STM32G0xx_HAL_Driver)
set(CMSIS_CORE ${CUBE_DRIVERS}/CMSIS/Include)
set(CMSIS_DEVICE ${CUBE_DRIVERS}/CMSIS/Device/ST/STM32G0xx/Include)

add_executable(orbit_stm32g0b1re_validation.elf
    main.c
    ${CUBE_PROJECT}/Src/system_stm32g0xx.c
    ${CUBE_PROJECT}/STM32CubeIDE/Application/Startup/startup_stm32g0b1retx.s
    ${HAL}/Src/stm32g0xx_hal.c
    ${HAL}/Src/stm32g0xx_hal_cortex.c
    ${HAL}/Src/stm32g0xx_hal_flash.c
    ${HAL}/Src/stm32g0xx_hal_flash_ex.c
    ${HAL}/Src/stm32g0xx_hal_gpio.c
    ${HAL}/Src/stm32g0xx_hal_pwr.c
    ${HAL}/Src/stm32g0xx_hal_pwr_ex.c
    ${HAL}/Src/stm32g0xx_hal_rcc.c
    ${HAL}/Src/stm32g0xx_hal_rcc_ex.c
    ${HAL}/Src/stm32g0xx_hal_uart.c
    ../orbit_board.c
    ../../common/client.c
    ${ORBIT_DIR}/adapters/stm32g0.c
    ${ORBIT_DIR}/adapters/mbedtls.c)
target_include_directories(orbit_stm32g0b1re_validation.elf PRIVATE
    ${ORBIT_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}/../../common
    ${CMAKE_CURRENT_LIST_DIR}
    ${HAL}/Inc
    ${CMSIS_CORE}
    ${CMSIS_DEVICE}
    ${CUBE_PROJECT}/Inc
    ${MBEDTLS_PATH}/include
    ${MBEDTLS_PATH}/library)
target_compile_definitions(orbit_stm32g0b1re_validation.elf PRIVATE
    STM32G0B1xx USE_HAL_DRIVER HAL_UART_MODULE_ENABLED
    ORBIT_APP_KEY="${ORBIT_APP_KEY}"
    ORBIT_CLIENT_ARENA_BYTES=${ORBIT_CLIENT_ARENA_BYTES})
target_compile_options(orbit_stm32g0b1re_validation.elf PRIVATE
    -Wall -Wextra)
target_link_options(orbit_stm32g0b1re_validation.elf PRIVATE
    -mcpu=cortex-m0plus -mthumb --specs=nano.specs --specs=nosys.specs
    -Wl,--gc-sections -Wl,--print-memory-usage
    -Wl,-Map=${CMAKE_CURRENT_BINARY_DIR}/orbit_stm32g0b1re_validation.map
    -T${CMAKE_CURRENT_LIST_DIR}/orbit_stm32g0b1re.ld)
target_link_libraries(orbit_stm32g0b1re_validation.elf PRIVATE
    orbit_embedded_transport orbit_embedded_client mbedcrypto)
