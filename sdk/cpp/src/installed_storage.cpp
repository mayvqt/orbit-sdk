#include "installed_storage.hpp"

#include "error.hpp"
#include "json.hpp"
#if defined(_WIN32)
#include "storage_windows.hpp"
#endif

#include <openssl/evp.h>

#include <array>
#include <cstdlib>
#include <limits>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace orbit::detail {
namespace {

[[noreturn]] void configuration_failure() {
    raise(ErrorKind::configuration, "configuration");
}

std::string hex_lower(const unsigned char* bytes, std::size_t count) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(count * 2);
    for (std::size_t i = 0; i < count; ++i) {
        out.push_back(digits[bytes[i] >> 4]);
        out.push_back(digits[bytes[i] & 15]);
    }
    return out;
}

#if defined(_WIN32)
std::string local_app_data() {
    const DWORD needed = GetEnvironmentVariableW(L"LOCALAPPDATA", nullptr, 0);
    if (needed < 2 || needed > 32768) configuration_failure();
    std::wstring wide(static_cast<std::size_t>(needed), L'\0');
    const DWORD copied = GetEnvironmentVariableW(L"LOCALAPPDATA", wide.data(), needed);
    if (copied == 0 || copied >= needed) configuration_failure();
    wide.resize(copied);
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(),
        static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) configuration_failure();
    std::string out(static_cast<std::size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(),
        static_cast<int>(wide.size()), out.data(), size, nullptr, nullptr) != size) {
        configuration_failure();
    }
    return out;
}
#endif

std::string default_state_parent() {
#if defined(__linux__)
    const char* state = std::getenv("XDG_STATE_HOME");
    if (state && *state) {
        std::string path(state);
        if (path.front() != '/' || path.find('\0') != std::string::npos) {
            configuration_failure();
        }
        return path + "/orbit";
    }
    const char* home = std::getenv("HOME");
    if (!home || !*home || home[0] != '/' || std::string_view(home).find('\0') != std::string_view::npos) {
        configuration_failure();
    }
    return std::string(home) + "/.local/state/orbit";
#elif defined(_WIN32)
    return local_app_data() + "\\Orbit";
#else
    configuration_failure();
#endif
}

} // namespace

std::string installed_scope_hash(const Config& config) {
    Json::Value scope(Json::objectValue);
    scope["api_origin"] = config.api_origin;
    scope["application_id"] = config.application_id;
    scope["environment_id"] = config.environment_id;
    scope["issuer"] = config.issuer;
    const auto canonical = encode_json(scope);
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0;
    if (EVP_Digest(canonical.data(), canonical.size(), digest.data(), &length,
                   EVP_sha256(), nullptr) != 1 || length != 32) {
        raise(ErrorKind::internal, "storage_initialization_failed");
    }
    return hex_lower(digest.data(), length);
}

std::string installed_provider() {
#if defined(__linux__)
    return "private_file";
#elif defined(_WIN32)
    return "windows_dpapi";
#else
    raise(ErrorKind::configuration, "installed_client_unsupported");
#endif
}

std::shared_ptr<InstalledStorage> open_installed_storage(
    const Config& config, std::optional<std::string> state_directory) {
    std::string directory;
    if (state_directory) {
        if (state_directory->empty() || state_directory->front() != '/' ||
            state_directory->find('\0') != std::string::npos ||
            state_directory->size() > 4096) {
#if defined(_WIN32)
            if (state_directory->empty() || state_directory->size() > 32767 ||
                state_directory->find('\0') != std::string::npos) {
                configuration_failure();
            }
#else
            configuration_failure();
#endif
        }
        directory = std::move(*state_directory);
    } else {
        directory = default_state_parent() + "/" + installed_scope_hash(config);
    }
#if defined(__linux__)
    return open_linux_installed_storage(std::move(directory));
#elif defined(_WIN32)
    return storage_windows::open_installed(std::move(directory), config);
#else
    (void)config;
    (void)directory;
    raise(ErrorKind::configuration, "installed_client_unsupported");
#endif
}

} // namespace orbit::detail
