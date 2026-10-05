#pragma once

#include "orbit_sdk.hpp"

#include <string>
#include <string_view>

namespace orbit::detail {

[[noreturn]] inline void raise(ErrorKind kind, std::string code = {},
                               std::string request_id = {}) {
    throw Error(1, kind, std::move(code), std::move(request_id));
}

// Whether a validation denial proves the saved device credential is dead.
// Other denials, such as a suspension or expiry, only withhold access.
inline bool discards_credential(ErrorKind kind, std::string_view code) {
    if (kind != ErrorKind::denied) return false;
    for (std::string_view dead : {"invalid_credentials", "authentication_required",
                                  "reauthentication_required", "credential_expired",
                                  "credential_revoked", "licence_revoked", "licence_claimed",
                                  "device_mismatch"}) {
        if (code == dead) return true;
    }
    return false;
}

inline void check_cancelled(bool cancelled) {
    if (cancelled) raise(ErrorKind::cancelled, "cancelled");
}

} // namespace orbit::detail
