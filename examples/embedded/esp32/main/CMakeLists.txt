set(ORBIT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../../sdk/embedded)
if(NOT DEFINED ORBIT_APP_KEY)
    set(ORBIT_APP_KEY "$ENV{ORBIT_APP_KEY}")
endif()
set(ORBIT_CLIENT_ARENA_BYTES 32768 CACHE STRING "Default Orbit transaction arena bytes")
if(ORBIT_CLIENT_ARENA_BYTES LESS 8192 OR ORBIT_CLIENT_ARENA_BYTES GREATER 32768)
    message(FATAL_ERROR "ORBIT_CLIENT_ARENA_BYTES must be between 8192 and 32768")
endif()
idf_component_register(SRCS main.c ../../common/client.c
    ${ORBIT_DIR}/src/orbit_grant.c ${ORBIT_DIR}/src/orbit_json.c
    ${ORBIT_DIR}/src/orbit_prepare.c ${ORBIT_DIR}/src/orbit_jwks.c
    ${ORBIT_DIR}/src/orbit_client.c ${ORBIT_DIR}/src/orbit_wire.c ${ORBIT_DIR}/src/orbit_storage.c
    ${ORBIT_DIR}/src/orbit_app_key.c
    ${ORBIT_DIR}/adapters/http.c ${ORBIT_DIR}/adapters/platform.c
    ${ORBIT_DIR}/adapters/esp32.c ${ORBIT_DIR}/adapters/mbedtls.c
    INCLUDE_DIRS ${ORBIT_DIR}/include ../../common
    REQUIRES esp_wifi esp-tls esp_timer esp_partition mbedtls)
target_compile_definitions(${COMPONENT_LIB} PRIVATE ORBIT_APP_KEY=\"${ORBIT_APP_KEY}\")
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    ORBIT_CLIENT_ARENA_BYTES=${ORBIT_CLIENT_ARENA_BYTES})

if(ORBIT_ENABLE_OFFLINE)
 set(ORBIT_ENABLE_SERVICES ON)
 if(NOT DEFINED ORBIT_OFFLINE_PROFILE_FILE_BYTES)
  set(ORBIT_OFFLINE_PROFILE_FILE_BYTES 4096)
 endif()
 target_compile_definitions(${COMPONENT_LIB} PRIVATE ORBIT_ENABLE_OFFLINE=1 ORBIT_OFFLINE_PROFILE_FILE_BYTES=${ORBIT_OFFLINE_PROFILE_FILE_BYTES})
 target_sources(${COMPONENT_LIB} PRIVATE ${ORBIT_DIR}/src/orbit_offline.c)
endif()
if(ORBIT_ENABLE_SERVICES)
 target_compile_definitions(${COMPONENT_LIB} PRIVATE ORBIT_ENABLE_SERVICES=1)
 target_sources(${COMPONENT_LIB} PRIVATE ${ORBIT_DIR}/src/orbit_services_codec.c ${ORBIT_DIR}/src/orbit_limits.c ${ORBIT_DIR}/src/orbit_downloads.c ${ORBIT_DIR}/src/orbit_extensions.c ${ORBIT_DIR}/src/orbit_sessions.c)
endif()
