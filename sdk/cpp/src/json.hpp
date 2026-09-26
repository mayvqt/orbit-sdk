#pragma once

#include <json/json.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace orbit::detail {

Json::Value parse_json(std::string_view input, std::size_t limit = 65536);
bool json_has_top_level_member(std::string_view input, std::string_view member,
                               std::size_t limit = 65536);
std::string encode_json(const Json::Value& value);
std::int64_t json_int64(const Json::Value& value);

} // namespace orbit::detail
