cmake_minimum_required(VERSION 3.16)
project(orbit_embedded_core VERSION 0.3.1 LANGUAGES C)

include(CTest)

add_library(orbit_embedded_core STATIC src/orbit_grant.c src/orbit_json.c src/orbit_prepare.c src/orbit_jwks.c)
add_library(Orbit::EmbeddedCore ALIAS orbit_embedded_core)
target_include_directories(orbit_embedded_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(orbit_embedded_core PUBLIC c_std_11)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(orbit_embedded_core PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

add_library(orbit_embedded_client STATIC src/orbit_client.c src/orbit_wire.c src/orbit_storage.c)
add_library(Orbit::EmbeddedClient ALIAS orbit_embedded_client)
target_link_libraries(orbit_embedded_client PUBLIC orbit_embedded_core)
target_compile_features(orbit_embedded_client PUBLIC c_std_11)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(orbit_embedded_client PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

add_library(orbit_embedded_transport STATIC adapters/http.c adapters/bridge.c adapters/platform.c)
target_link_libraries(orbit_embedded_transport PUBLIC orbit_embedded_client)
target_compile_features(orbit_embedded_transport PUBLIC c_std_11)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(orbit_embedded_transport PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
option(ORBIT_BUILD_POSIX "Build the Linux HTTPS/storage adapter and physical bridge helper" OFF)
if(ORBIT_BUILD_POSIX)
    find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(CURL REQUIRED IMPORTED_TARGET libcurl)
    add_library(orbit_embedded_posix STATIC adapters/posix.c adapters/openssl.c)
    target_link_libraries(orbit_embedded_posix PUBLIC orbit_embedded_client OpenSSL::Crypto PkgConfig::CURL)
    target_compile_options(orbit_embedded_posix PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_executable(orbit_bridge_host adapters/bridge_host.c)
    target_link_libraries(orbit_bridge_host PRIVATE orbit_embedded_posix)
endif()

if(BUILD_TESTING)
    find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(ORBIT_GENERATED_VECTORS ${CMAKE_CURRENT_BINARY_DIR}/orbit_generated_vectors.h)
    set(ORBIT_GRANT_VECTORS ${CMAKE_CURRENT_SOURCE_DIR}/../../contracts/sdk/grants.json CACHE FILEPATH "Shared grant vectors")
    add_custom_command(
        OUTPUT ${ORBIT_GENERATED_VECTORS}
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/generate_vectors.py
            --source ${ORBIT_GRANT_VECTORS}
            --output ${ORBIT_GENERATED_VECTORS}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/generate_vectors.py
            ${ORBIT_GRANT_VECTORS}
        VERBATIM
    )
    add_custom_target(orbit_embedded_generate_vectors DEPENDS ${ORBIT_GENERATED_VECTORS})
    add_executable(orbit_embedded_vector_tests
        tests/test_vectors.c tests/openssl_adapter.c adapters/openssl.c)
    add_dependencies(orbit_embedded_vector_tests orbit_embedded_generate_vectors)
    target_include_directories(orbit_embedded_vector_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(orbit_embedded_vector_tests PRIVATE orbit_embedded_core OpenSSL::Crypto)
    target_compile_features(orbit_embedded_vector_tests PRIVATE c_std_11)
    add_test(NAME orbit_embedded_shared_grant_vectors COMMAND orbit_embedded_vector_tests)

    add_executable(orbit_embedded_core_tests
        tests/test_core.c tests/openssl_adapter.c adapters/openssl.c)
    add_dependencies(orbit_embedded_core_tests orbit_embedded_generate_vectors)
    target_include_directories(orbit_embedded_core_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(orbit_embedded_core_tests PRIVATE orbit_embedded_core OpenSSL::Crypto)
    target_compile_features(orbit_embedded_core_tests PRIVATE c_std_11)
    add_test(NAME orbit_embedded_core_bounds COMMAND orbit_embedded_core_tests)

    set(ORBIT_TEST_PRIVATE_KEY ${CMAKE_CURRENT_SOURCE_DIR}/../rust/tests/fixtures/es256-test-private.pem CACHE FILEPATH "Public synthetic signing fixture")
    add_executable(orbit_embedded_client_tests tests/test_client.c tests/openssl_adapter.c adapters/openssl.c)
    add_dependencies(orbit_embedded_client_tests orbit_embedded_generate_vectors)
    target_include_directories(orbit_embedded_client_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_BINARY_DIR})
    target_compile_definitions(orbit_embedded_client_tests PRIVATE ORBIT_TEST_PRIVATE_KEY="${ORBIT_TEST_PRIVATE_KEY}")
    target_link_libraries(orbit_embedded_client_tests PRIVATE orbit_embedded_client OpenSSL::Crypto)
    add_test(NAME orbit_embedded_client_lifecycle COMMAND orbit_embedded_client_tests)

    add_executable(orbit_embedded_transport_tests tests/test_transport.c)
    target_link_libraries(orbit_embedded_transport_tests PRIVATE orbit_embedded_transport)
    add_test(NAME orbit_embedded_transport_bounds COMMAND orbit_embedded_transport_tests)
    if(ORBIT_BUILD_POSIX)
        add_executable(orbit_embedded_posix_tests tests/test_posix.c)
        target_link_libraries(orbit_embedded_posix_tests PRIVATE orbit_embedded_posix)
        add_test(NAME orbit_embedded_posix_storage COMMAND orbit_embedded_posix_tests)
        add_test(NAME orbit_embedded_bridge_host COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_bridge_host.py
            ${CMAKE_CROSSCOMPILING_EMULATOR} $<TARGET_FILE:orbit_bridge_host>)
    endif()
endif()
