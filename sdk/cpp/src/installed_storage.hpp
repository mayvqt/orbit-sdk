#pragma once

#include "platform.hpp"

#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace orbit::detail {

class InstalledStorage {
public:
    virtual ~InstalledStorage() = default;
    virtual bool initialization_needed() const noexcept = 0;
    virtual std::optional<std::string> load() = 0;
    virtual void initialize(std::string_view bytes) = 0;
    virtual void save(std::string_view bytes) = 0;
    virtual std::string_view provider() const noexcept = 0;
};

std::shared_ptr<InstalledStorage> open_installed_storage(
    const Config& config, std::optional<std::string> state_directory);
std::string installed_scope_hash(const Config& config);
std::string installed_provider();

#if defined(__linux__)
std::shared_ptr<InstalledStorage> open_linux_installed_storage(std::string directory);
#elif defined(_WIN32)
std::shared_ptr<InstalledStorage> open_windows_installed_storage(
    std::string directory, const Config& config);
#endif

} // namespace orbit::detail
