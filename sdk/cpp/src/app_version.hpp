#pragma once

#include "json.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace orbit::detail {

// N[.N[.N[.N]]][-PRE][+BUILD] in at most 32 bytes.
bool valid_app_version(std::string_view value);

// Orbit-Client value, or nullopt when a part is outside the header grammar.
std::optional<std::string> format_client_header(std::string_view language,
                                                std::string_view sdk_version,
                                                std::string_view platform);

// This SDK's Orbit-Client value.
const std::string& client_header();

// Optional update_available version; a malformed hint invalidates the reply.
std::optional<std::string> update_hint(const Json::Value& reply);

} // namespace orbit::detail
