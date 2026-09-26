set(ORBIT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../../sdk/embedded)
idf_component_register(SRCS main.c ../../common/client.c
    ${ORBIT_DIR}/src/orbit_grant.c ${ORBIT_DIR}/src/orbit_json.c
    ${ORBIT_DIR}/src/orbit_prepare.c ${ORBIT_DIR}/src/orbit_jwks.c
    ${ORBIT_DIR}/src/orbit_client.c ${ORBIT_DIR}/src/orbit_wire.c ${ORBIT_DIR}/src/orbit_storage.c
    ${ORBIT_DIR}/adapters/http.c ${ORBIT_DIR}/adapters/platform.c
    ${ORBIT_DIR}/adapters/esp32.c ${ORBIT_DIR}/adapters/mbedtls.c
    INCLUDE_DIRS ${ORBIT_DIR}/include ../../common
    REQUIRES esp_wifi esp-tls esp_timer esp_partition mbedtls)
