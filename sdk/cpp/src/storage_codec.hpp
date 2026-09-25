#pragma once

#include "platform.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace orbit::detail::storage_codec {

constexpr std::size_t max_plaintext = 32 * 1024;
constexpr std::uint64_t max_generation = 0x7fff'ffff'ffff'ffffULL;

std::array<unsigned char, 32> entropy(const Config& config);
std::string encode(const Config& config, std::uint64_t generation,
                   const std::optional<Json::Value>& credential);
std::pair<std::uint64_t, std::optional<Json::Value>> decode(
    const Config& config, std::string_view bytes);

} // namespace orbit::detail::storage_codec
