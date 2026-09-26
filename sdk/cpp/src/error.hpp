#pragma once

#include "orbit_sdk.hpp"

#include <string>

namespace orbit::detail {

[[noreturn]] inline void raise(ErrorKind kind, std::string code = {},
                               std::string request_id = {}) {
    throw Error(1, kind, std::move(code), std::move(request_id));
}

inline void check_cancelled(bool cancelled) {
    if (cancelled) raise(ErrorKind::cancelled, "cancelled");
}

} // namespace orbit::detail
