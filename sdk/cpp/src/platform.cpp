#include "platform.hpp"
#include "platform_test_support.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#if defined(__linux__)
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#elif defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace orbit {
namespace {

constexpr std::size_t kMaximumSmbiosBytes = 1024 * 1024;

[[noreturn]] void configuration_error() {
    throw Error(1, ErrorKind::configuration, "configuration", {});
}

[[noreturn]] void identity_error() {
    throw Error(1, ErrorKind::denied, "device_identity_unavailable", {});
}

bool opaque(std::string_view value) {
    return !value.empty() && value.size() <= 128 &&
           std::all_of(value.begin(), value.end(), [](unsigned char c) {
               return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '_' || c == '-';
           });
}

std::array<unsigned char, 32> sha256(std::string_view input) {
    std::array<unsigned char, 32> output{};
    unsigned int length = 0;
    if (EVP_Digest(input.data(), input.size(), output.data(), &length,
                   EVP_sha256(), nullptr) != 1 || length != output.size()) {
        throw Error(1, ErrorKind::internal, "cryptographic_failure", {});
    }
    return output;
}

std::string hex_lower(const unsigned char* bytes, std::size_t length) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(length * 2);
    for (std::size_t i = 0; i < length; ++i) {
        output.push_back(digits[bytes[i] >> 4]);
        output.push_back(digits[bytes[i] & 0x0f]);
    }
    return output;
}

std::string base64url_without_padding(const unsigned char* bytes,
                                     std::size_t length) {
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string output;
    output.reserve((length * 4 + 2) / 3);
    std::size_t i = 0;
    for (; i + 3 <= length; i += 3) {
        const std::uint32_t value =
            (static_cast<std::uint32_t>(bytes[i]) << 16) |
            (static_cast<std::uint32_t>(bytes[i + 1]) << 8) |
            static_cast<std::uint32_t>(bytes[i + 2]);
        output.push_back(alphabet[(value >> 18) & 63]);
        output.push_back(alphabet[(value >> 12) & 63]);
        output.push_back(alphabet[(value >> 6) & 63]);
        output.push_back(alphabet[value & 63]);
    }
    const auto remaining = length - i;
    if (remaining == 1) {
        const auto value = static_cast<std::uint32_t>(bytes[i]) << 16;
        output.push_back(alphabet[(value >> 18) & 63]);
        output.push_back(alphabet[(value >> 12) & 63]);
    } else if (remaining == 2) {
        const auto value = (static_cast<std::uint32_t>(bytes[i]) << 16) |
                           (static_cast<std::uint32_t>(bytes[i + 1]) << 8);
        output.push_back(alphabet[(value >> 18) & 63]);
        output.push_back(alphabet[(value >> 12) & 63]);
        output.push_back(alphabet[(value >> 6) & 63]);
    }
    return output;
}

bool ascii_space(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' ||
           c == '\f';
}

std::string normalized_machine_id(std::string_view input) {
    std::size_t begin = 0;
    std::size_t end = input.size();
    while (begin < end && ascii_space(input[begin])) {
        ++begin;
    }
    while (end > begin && ascii_space(input[end - 1])) {
        --end;
    }
    std::string normalized;
    normalized.reserve(end - begin);
    for (std::size_t i = begin; i < end; ++i) {
        const auto c = static_cast<unsigned char>(input[i]);
        if (c == '-') {
            continue;
        }
        if (c >= 'A' && c <= 'Z') {
            normalized.push_back(static_cast<char>(c + ('a' - 'A')));
        } else {
            normalized.push_back(static_cast<char>(c));
        }
    }
    return normalized;
}

bool valid_machine_id(std::string_view value) {
    if (value.size() != 32) {
        return false;
    }
    bool all_zero = true;
    bool all_f = true;
    for (const auto c : value) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex) {
            return false;
        }
        all_zero &= c == '0';
        all_f &= c == 'f';
    }
    return !all_zero && !all_f;
}

std::uint32_t read_u32_le(std::string_view bytes, std::size_t offset) {
    return static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset])) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset + 1])) << 8) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset + 2])) << 16) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset + 3])) << 24);
}

std::optional<std::string> parse_smbios_uuid_impl(std::string_view raw) {
    if (raw.size() < 8 || raw.size() > kMaximumSmbiosBytes ||
        static_cast<unsigned char>(raw[1]) < 2 ||
        (static_cast<unsigned char>(raw[1]) == 2 &&
         static_cast<unsigned char>(raw[2]) < 6)) {
        return std::nullopt;
    }
    const auto declared = static_cast<std::size_t>(read_u32_le(raw, 4));
    if (declared != raw.size() - 8) {
        return std::nullopt;
    }
    const auto payload = raw.substr(8);
    std::size_t cursor = 0;
    std::optional<std::string> identity;
    while (cursor < payload.size()) {
        if (payload.size() - cursor < 4) {
            return std::nullopt;
        }
        const auto type = static_cast<unsigned char>(payload[cursor]);
        const auto length = static_cast<std::size_t>(
            static_cast<unsigned char>(payload[cursor + 1]));
        if (length < 4 || length > payload.size() - cursor) {
            return std::nullopt;
        }
        const auto formatted_end = cursor + length;
        const auto terminator = payload.find(std::string_view("\0\0", 2), formatted_end);
        if (terminator == std::string_view::npos) {
            return std::nullopt;
        }
        cursor = terminator + 2;
        if (type == 1) {
            if (identity || length < 25) {
                return std::nullopt;
            }
            std::array<unsigned char, 16> uuid{};
            for (std::size_t i = 0; i < uuid.size(); ++i) {
                uuid[i] = static_cast<unsigned char>(payload[formatted_end - length + 8 + i]);
            }
            const bool all_zero = std::all_of(uuid.begin(), uuid.end(),
                                              [](unsigned char c) { return c == 0; });
            const bool all_ff = std::all_of(uuid.begin(), uuid.end(),
                                            [](unsigned char c) { return c == 0xff; });
            if (all_zero || all_ff) {
                return std::nullopt;
            }
            std::reverse(uuid.begin(), uuid.begin() + 4);
            std::reverse(uuid.begin() + 4, uuid.begin() + 6);
            std::reverse(uuid.begin() + 6, uuid.begin() + 8);
            auto canonical = hex_lower(uuid.data(), uuid.size());
            canonical.insert(20, "-");
            canonical.insert(16, "-");
            canonical.insert(12, "-");
            canonical.insert(8, "-");
            identity = std::move(canonical);
        } else if (type == 127) {
            return identity;
        }
    }
    return std::nullopt;
}

std::string read_linux_machine_id() {
#if defined(__linux__)
    const int fd = ::open("/etc/machine-id", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        identity_error();
    }
    std::array<char, 257> bytes{};
    std::size_t size = 0;
    while (size < bytes.size()) {
        const auto count = ::read(fd, bytes.data() + size, bytes.size() - size);
        if (count == 0) {
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            ::close(fd);
            identity_error();
        }
        size += static_cast<std::size_t>(count);
    }
    ::close(fd);
    if (size > 256) {
        identity_error();
    }
    return std::string(bytes.data(), size);
#else
    identity_error();
#endif
}

#if defined(_WIN32)
std::string read_windows_machine_uuid() {
    static constexpr DWORD kRsmb = 0x52534D42;
    const DWORD required = GetSystemFirmwareTable(kRsmb, 0, nullptr, 0);
    if (required < 8 || required > kMaximumSmbiosBytes) {
        identity_error();
    }
    std::vector<char> raw(required);
    const DWORD read = GetSystemFirmwareTable(kRsmb, 0, raw.data(), required);
    if (read != required) {
        identity_error();
    }
    const auto parsed = detail::testing::parse_smbios_uuid(
        std::string_view(raw.data(), raw.size()));
    if (!parsed) {
        identity_error();
    }
    return *parsed;
}
#endif

} // namespace

std::string new_installation_id() {
    std::array<unsigned char, 24> random{};
    if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
        throw Error(1, ErrorKind::internal, "cryptographic_failure", {});
    }
    return base64url_without_padding(random.data(), random.size());
}

std::string machine_fingerprint(std::string_view application_id,
                                std::string_view environment_id,
                                std::string_view family,
                                std::string_view identity) {
    if (!opaque(application_id) || !opaque(environment_id) ||
        (family != "linux" && family != "windows")) {
        configuration_error();
    }
    const auto normalized = normalized_machine_id(identity);
    if (!valid_machine_id(normalized)) {
        identity_error();
    }
    std::string preimage = "orbit-machine-v1\n";
    preimage.append(application_id);
    preimage.push_back('\n');
    preimage.append(environment_id);
    preimage.push_back('\n');
    preimage.append(family);
    preimage.push_back('\n');
    preimage.append(normalized);
    const auto digest = sha256(preimage);
    return hex_lower(digest.data(), digest.size());
}

std::string native_fingerprint(std::string_view application_id,
                               std::string_view environment_id) {
    if (!opaque(application_id) || !opaque(environment_id)) {
        configuration_error();
    }
#if defined(__linux__)
    const auto identity = read_linux_machine_id();
    return machine_fingerprint(application_id, environment_id, "linux", identity);
#elif defined(_WIN32)
    const auto identity = read_windows_machine_uuid();
    return machine_fingerprint(application_id, environment_id, "windows", identity);
#else
    identity_error();
#endif
}

namespace detail {

std::int64_t elapsed_nanoseconds() {
#if defined(__linux__)
    timespec value{};
    if (::clock_gettime(CLOCK_BOOTTIME, &value) != 0 || value.tv_sec < 0 ||
        value.tv_nsec < 0 || value.tv_nsec >= 1'000'000'000) {
        throw Error(1, ErrorKind::clock_uncertain, "clock_uncertain", {});
    }
    constexpr auto max = std::numeric_limits<std::int64_t>::max();
    if (static_cast<std::uint64_t>(value.tv_sec) >
            static_cast<std::uint64_t>(max / 1'000'000'000) ||
        (static_cast<std::uint64_t>(value.tv_sec) ==
             static_cast<std::uint64_t>(max / 1'000'000'000) &&
         value.tv_nsec > max % 1'000'000'000)) {
        throw Error(1, ErrorKind::clock_uncertain, "clock_uncertain", {});
    }
    return static_cast<std::int64_t>(value.tv_sec) * 1'000'000'000 +
           static_cast<std::int64_t>(value.tv_nsec);
#elif defined(_WIN32)
    ULONGLONG ticks = 0;
    QueryInterruptTimePrecise(&ticks);
    constexpr ULONGLONG per_second = 10'000'000;
    constexpr ULONGLONG max_seconds =
        static_cast<ULONGLONG>(std::numeric_limits<std::int64_t>::max()) /
        1'000'000'000ULL;
    if (ticks / per_second > max_seconds) {
        throw Error(1, ErrorKind::clock_uncertain, "clock_uncertain", {});
    }
    const auto whole_seconds = ticks / per_second;
    const auto remainder = ticks % per_second;
    constexpr auto max_nanoseconds = static_cast<ULONGLONG>(
        std::numeric_limits<std::int64_t>::max());
    if (whole_seconds == max_seconds && remainder >
            (max_nanoseconds - whole_seconds * 1'000'000'000ULL) / 100ULL) {
        throw Error(1, ErrorKind::clock_uncertain, "clock_uncertain", {});
    }
    return static_cast<std::int64_t>(whole_seconds * 1'000'000'000ULL +
                                     remainder * 100ULL);
#else
    throw Error(1, ErrorKind::clock_uncertain, "clock_uncertain", {});
#endif
}

std::int64_t wall_seconds() {
#if defined(__linux__)
    timespec value{};
    if (::clock_gettime(CLOCK_REALTIME, &value) != 0 || value.tv_sec < 0 ||
        value.tv_nsec < 0 || value.tv_nsec >= 1'000'000'000 ||
        static_cast<std::uint64_t>(value.tv_sec) >
            static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        throw Error(1, ErrorKind::clock_uncertain, "clock_uncertain", {});
    }
    return static_cast<std::int64_t>(value.tv_sec);
#elif defined(_WIN32)
    FILETIME time{};
    GetSystemTimeAsFileTime(&time);
    ULARGE_INTEGER ticks{};
    ticks.LowPart = time.dwLowDateTime;
    ticks.HighPart = time.dwHighDateTime;
    constexpr ULONGLONG epoch = 116'444'736'000'000'000ULL;
    if (ticks.QuadPart < epoch) {
        throw Error(1, ErrorKind::clock_uncertain, "clock_uncertain", {});
    }
    const auto seconds = (ticks.QuadPart - epoch) / 10'000'000ULL;
    if (seconds > static_cast<ULONGLONG>(std::numeric_limits<std::int64_t>::max())) {
        throw Error(1, ErrorKind::clock_uncertain, "clock_uncertain", {});
    }
    return static_cast<std::int64_t>(seconds);
#else
    throw Error(1, ErrorKind::clock_uncertain, "clock_uncertain", {});
#endif
}

namespace testing {

std::optional<std::string> parse_smbios_uuid(std::string_view raw) {
    return parse_smbios_uuid_impl(raw);
}

} // namespace testing
} // namespace detail
} // namespace orbit
