#pragma once

#include "platform.hpp"

namespace orbit::detail::persistent_codec {

constexpr std::size_t max_plaintext = 64 * 1024;
constexpr std::size_t max_jws = 16 * 1024;
constexpr std::uint64_t max_generation = 0x7fff'ffff'ffff'ffffULL;

Json::Value empty_record(const Config& config, std::string_view provider);
Json::Value decode(const Config& config, std::string_view provider,
                   std::string_view bytes);
std::string encode(const Config& config, std::string_view provider,
                   const Json::Value& record);

} // namespace orbit::detail::persistent_codec
