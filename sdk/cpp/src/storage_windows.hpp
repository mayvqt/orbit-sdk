#pragma once

#include "platform.hpp"

#include <memory>

namespace orbit::detail::storage_windows {

std::shared_ptr<CredentialStorage> open(const Config& config);

} // namespace orbit::detail::storage_windows
