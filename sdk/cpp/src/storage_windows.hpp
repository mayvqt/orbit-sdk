#pragma once

#include "platform.hpp"
#include "installed_storage.hpp"

#include <memory>

namespace orbit::detail::storage_windows {

#if defined(ORBIT_SDK_TESTING) && defined(_WIN32)
enum class InstalledWriteFault { none, fenced, temporary_written, replaced };
void set_installed_write_fault(InstalledWriteFault fault);
#endif

std::shared_ptr<CredentialStorage> open(const Config& config);
std::shared_ptr<InstalledStorage> open_installed(std::string directory,
                                                const Config& config);

} // namespace orbit::detail::storage_windows
