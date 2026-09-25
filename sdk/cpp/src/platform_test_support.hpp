#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace orbit::detail::testing {

std::optional<std::string> parse_smbios_uuid(std::string_view raw);

} // namespace orbit::detail::testing
