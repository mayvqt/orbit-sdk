cmake_minimum_required(VERSION 3.16)
project(orbit_embedded_core VERSION 0.4.0 LANGUAGES C)

include(CTest)

add_library(orbit_embedded_core STATIC src/orbit_grant.c src/orbit_json.c src/orbit_prepare.c src/orbit_jwks.c)
add_library(Orbit::EmbeddedCore ALIAS orbit_embedded_core)
target_include_directories(orbit_embedded_core PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_compile_features(orbit_embedded_core PUBLIC c_std_11)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(orbit_embedded_core PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

option(ORBIT_ENABLE_SERVICES "Enable floating, usage, resources and licensed downloads" OFF)
option(ORBIT_ENABLE_OFFLINE "Enable bounded long-term offline files" OFF)
if(ORBIT_ENABLE_OFFLINE)
 set(ORBIT_ENABLE_SERVICES ON)
endif()
add_library(orbit_embedded_client STATIC src/orbit_client.c src/orbit_wire.c src/orbit_storage.c src/orbit_app_key.c)
add_library(Orbit::EmbeddedClient ALIAS orbit_embedded_client)
target_link_libraries(orbit_embedded_client PUBLIC orbit_embedded_core)
target_compile_features(orbit_embedded_client PUBLIC c_std_11)
set(ORBIT_CLIENT_ARENA_BYTES 32768 CACHE STRING "Default caller-owned embedded client arena size")
if(ORBIT_CLIENT_ARENA_BYTES LESS 8192 OR ORBIT_CLIENT_ARENA_BYTES GREATER 32768)
    message(FATAL_ERROR "ORBIT_CLIENT_ARENA_BYTES must be between 8192 and 32768")
endif()
target_compile_definitions(orbit_embedded_client PUBLIC ORBIT_CLIENT_ARENA_BYTES=${ORBIT_CLIENT_ARENA_BYTES})
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
    set(ORBIT_GENERATED_APP_KEY_VECTORS ${CMAKE_CURRENT_BINARY_DIR}/orbit_generated_app_key_vectors.h)
    set(ORBIT_APP_KEY_VECTORS ${CMAKE_CURRENT_SOURCE_DIR}/../../contracts/sdk/app-keys.json CACHE FILEPATH "Shared app-key vectors")
    add_custom_command(
        OUTPUT ${ORBIT_GENERATED_APP_KEY_VECTORS}
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/generate_app_key_vectors.py
            --source ${ORBIT_APP_KEY_VECTORS}
            --output ${ORBIT_GENERATED_APP_KEY_VECTORS}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/generate_app_key_vectors.py
            ${ORBIT_APP_KEY_VECTORS}
        VERBATIM
    )
    add_custom_target(orbit_embedded_generate_app_key_vectors DEPENDS ${ORBIT_GENERATED_APP_KEY_VECTORS})
    add_executable(orbit_embedded_app_key_tests tests/test_app_key.c)
    add_dependencies(orbit_embedded_app_key_tests orbit_embedded_generate_app_key_vectors)
    target_include_directories(orbit_embedded_app_key_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(orbit_embedded_app_key_tests PRIVATE orbit_embedded_client)
    target_compile_features(orbit_embedded_app_key_tests PRIVATE c_std_11)
    add_test(NAME orbit_embedded_shared_app_key_vectors COMMAND orbit_embedded_app_key_tests)

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

if(ORBIT_ENABLE_SERVICES)
 target_sources(orbit_embedded_client PRIVATE src/orbit_services_codec.c src/orbit_limits.c src/orbit_downloads.c src/orbit_extensions.c src/orbit_sessions.c)
 target_compile_definitions(orbit_embedded_core PUBLIC ORBIT_ENABLE_SERVICES=1)
endif()

if(ORBIT_ENABLE_SERVICES AND BUILD_TESTING)
 add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/orbit_generated_signed_vectors.h
 COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/generate_signed_vectors.py --source ${CMAKE_CURRENT_SOURCE_DIR}/../../contracts/sdk --output ${CMAKE_CURRENT_BINARY_DIR}/orbit_generated_signed_vectors.h
 DEPENDS tests/generate_signed_vectors.py ../../contracts/sdk/offline-files.json ../../contracts/sdk/session-grants.json VERBATIM)
 add_executable(orbit_embedded_signed_tests tests/test_signed.c tests/openssl_adapter.c adapters/openssl.c ${CMAKE_CURRENT_BINARY_DIR}/orbit_generated_signed_vectors.h)
 target_include_directories(orbit_embedded_signed_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_BINARY_DIR})
 target_link_libraries(orbit_embedded_signed_tests PRIVATE orbit_embedded_core OpenSSL::Crypto)
 add_test(NAME orbit_embedded_signed_corpora COMMAND orbit_embedded_signed_tests)
endif()

if(ORBIT_ENABLE_OFFLINE)
 set(ORBIT_OFFLINE_PROFILE_FILE_BYTES 4096 CACHE STRING "Maximum signed offline file bytes (4096 or 16384)")
 target_compile_definitions(orbit_embedded_core PUBLIC ORBIT_ENABLE_OFFLINE=1 ORBIT_OFFLINE_PROFILE_FILE_BYTES=${ORBIT_OFFLINE_PROFILE_FILE_BYTES})
 target_sources(orbit_embedded_client PRIVATE src/orbit_offline.c)
endif()
if(ORBIT_ENABLE_SERVICES AND BUILD_TESTING)
 add_executable(orbit_embedded_extension_tests tests/test_extensions.c tests/openssl_adapter.c adapters/openssl.c)
 add_dependencies(orbit_embedded_extension_tests orbit_embedded_generate_vectors)
 target_include_directories(orbit_embedded_extension_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_BINARY_DIR})
 target_compile_definitions(orbit_embedded_extension_tests PRIVATE ORBIT_TEST_PRIVATE_KEY="${ORBIT_TEST_PRIVATE_KEY}")
 target_link_libraries(orbit_embedded_extension_tests PRIVATE orbit_embedded_client OpenSSL::Crypto)
 add_test(NAME orbit_embedded_extended_lifecycle COMMAND orbit_embedded_extension_tests)
endif()
if(ORBIT_ENABLE_SERVICES AND BUILD_TESTING)
 add_executable(orbit_embedded_download_tests tests/test_downloads.c tests/openssl_adapter.c adapters/openssl.c)
 target_include_directories(orbit_embedded_download_tests PRIVATE tests)
 target_link_libraries(orbit_embedded_download_tests PRIVATE orbit_embedded_client OpenSSL::Crypto)
 add_test(NAME orbit_embedded_streaming COMMAND orbit_embedded_download_tests)
endif()
if(ORBIT_ENABLE_OFFLINE AND BUILD_TESTING)
 add_executable(orbit_embedded_offline_journal_tests tests/test_offline_journal.c)
 target_link_libraries(orbit_embedded_offline_journal_tests PRIVATE orbit_embedded_client)
 add_test(NAME orbit_embedded_offline_journal COMMAND orbit_embedded_offline_journal_tests)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
set_target_properties(orbit_embedded_core PROPERTIES EXPORT_NAME EmbeddedCore)
set_target_properties(orbit_embedded_client PROPERTIES EXPORT_NAME EmbeddedClient)
set_target_properties(orbit_embedded_transport PROPERTIES EXPORT_NAME EmbeddedTransport)
install(TARGETS orbit_embedded_core orbit_embedded_client orbit_embedded_transport
 EXPORT OrbitEmbeddedTargets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
if(ORBIT_BUILD_POSIX)
 set_target_properties(orbit_embedded_posix PROPERTIES EXPORT_NAME EmbeddedPosix)
 install(TARGETS orbit_embedded_posix EXPORT OrbitEmbeddedTargets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
configure_package_config_file(cmake/OrbitEmbeddedConfig.cmake.in
 ${CMAKE_CURRENT_BINARY_DIR}/OrbitEmbeddedConfig.cmake
 INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OrbitEmbedded)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/OrbitEmbeddedConfigVersion.cmake
 VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(EXPORT OrbitEmbeddedTargets NAMESPACE Orbit:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OrbitEmbedded)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/OrbitEmbeddedConfig.cmake
 ${CMAKE_CURRENT_BINARY_DIR}/OrbitEmbeddedConfigVersion.cmake
 DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OrbitEmbedded)
