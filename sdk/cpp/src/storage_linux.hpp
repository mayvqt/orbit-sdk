#pragma once

#include "platform.hpp"

#include <chrono>
#include <memory>
#include <string_view>

namespace orbit::detail::storage_linux {

std::shared_ptr<CredentialStorage> open(const Config& config,
                                        std::string_view helper = "/usr/bin/secret-tool",
                                        std::chrono::milliseconds deadline =
                                            std::chrono::seconds(5));

} // namespace orbit::detail::storage_linux
