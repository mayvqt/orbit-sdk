#pragma once

#include <optional>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace orbit::detail::testing {

std::optional<std::string> parse_smbios_uuid(std::string_view raw);
std::optional<std::string> normalize_macos_platform_uuid(std::string_view raw);
std::optional<std::int64_t> mach_ticks_to_nanoseconds(
    std::uint64_t ticks, std::uint32_t numerator, std::uint32_t denominator);

template <typename T, typename Release>
class ScopedResource {
public:
    ScopedResource(T value, Release release) : value_(value), release_(std::move(release)) {}
    ~ScopedResource() { if (value_ != T{}) release_(value_); }
    ScopedResource(const ScopedResource&) = delete;
    ScopedResource& operator=(const ScopedResource&) = delete;
    T get() const noexcept { return value_; }
private:
    T value_;
    Release release_;
};

} // namespace orbit::detail::testing
