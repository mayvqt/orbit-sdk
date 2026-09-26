#pragma once

#include "platform.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace orbit::detail::storage_linux_internal {

class Lease {
public:
    Lease();
    ~Lease();
    Lease(Lease&&) noexcept;
    Lease& operator=(Lease&&) noexcept;
    Lease(const Lease&) = delete;
    Lease& operator=(const Lease&) = delete;

    static Lease open(std::string_view directory);
    bool created() const;
    const std::string& directory() const;
    void verify() const;
    void begin_write();
    void complete_write();

private:
    struct State;
    explicit Lease(std::unique_ptr<State> state);
    std::unique_ptr<State> state_;
};

std::optional<std::string> lookup(std::string_view executable,
                                  std::string_view scope,
                                  std::chrono::milliseconds deadline);
void store(std::string_view executable, std::string_view scope,
           std::string_view record, std::chrono::milliseconds deadline);

} // namespace orbit::detail::storage_linux_internal
