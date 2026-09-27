#include "orbit_client.h"
#include <stddef.h>
#ifdef ORBIT_ENABLE_SERVICES
#include "orbit_extensions.h"
#include "orbit_downloads.h"
#endif
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
    case 21:return offsetof(orbit_client_config_t,app_version);
    case 22:return offsetof(orbit_http_request_t,client);
    case 23:return offsetof(orbit_access_snapshot_t,update_available);
#ifdef ORBIT_ENABLE_SERVICES
    case 9:return sizeof(orbit_client_extension_t);
    case 10:return sizeof(orbit_counter_t);
    case 11:return sizeof(orbit_limit_result_t);
    case 12:return sizeof(orbit_session_snapshot_t);
    case 13:return sizeof(orbit_artifact_t);
    case 14:return sizeof(orbit_release_t);
    case 15:return sizeof(orbit_update_t);
    case 16:return sizeof(orbit_download_authorization_t);
    case 17:return sizeof(orbit_operation_t);
    case 18:return sizeof(orbit_download_io_t);
    case 19:return sizeof(orbit_download_response_t);
    case 20:return sizeof(orbit_offline_config_t);
#endif
    default:return 0;
    }
}
