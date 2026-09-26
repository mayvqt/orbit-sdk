#include "orbit_client.h"
#include <stddef.h>
/* Linked only when the Rust unit test requests it; verifies the actual C ABI. */
size_t orbit_rust_layout(unsigned index) {
    switch(index) {
    case 0:return sizeof(orbit_client_t);
    case 1:return _Alignof(orbit_client_t);
    case 2:return sizeof(orbit_client_config_t);
    case 3:return sizeof(orbit_client_services_t);
    case 4:return sizeof(orbit_http_request_t);
    case 5:return sizeof(orbit_access_snapshot_t);
    case 6:return offsetof(orbit_client_services_t,crypto);
    case 7:return offsetof(orbit_http_request_t,post);
    case 8:return offsetof(orbit_access_snapshot_t,allowed);
    default:return 0;
    }
}
