#include "platform.hpp"

#include "storage_linux.hpp"
#include "storage_windows.hpp"

#include <limits>
#include <mutex>

namespace orbit::detail {
namespace {

[[noreturn]] void storage_failure() {
    throw Error(1, ErrorKind::storage, "storage", {});
}

class MemoryStorage final : public CredentialStorage {
public:
    std::uint64_t version() override {
        std::lock_guard<std::mutex> lock(mutex_);
        return generation_;
    }

    std::pair<std::uint64_t, std::optional<Json::Value>> load() override {
        std::lock_guard<std::mutex> lock(mutex_);
        return {generation_, credential_};
    }

    void save(std::uint64_t expected_version,
              const Json::Value& credential) override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (expected_version != generation_) {
            throw Error(1, ErrorKind::stale_response, "stale_response", {});
        }
        credential_ = credential;
    }

    std::uint64_t invalidate() override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (generation_ == 0x7fff'ffff'ffff'ffffULL) {
            storage_failure();
        }
        ++generation_;
        credential_.reset();
        return generation_;
    }

private:
    std::mutex mutex_;
    std::uint64_t generation_ = 0;
    std::optional<Json::Value> credential_;
};

} // namespace

std::shared_ptr<CredentialStorage> open_storage(const Config& config) {
    switch (config.storage.mode) {
    case StorageMode::memory:
        if (!config.storage.path.empty()) {
            storage_failure();
        }
        return std::make_shared<MemoryStorage>();
    case StorageMode::windows_dpapi:
#if defined(_WIN32)
        if (config.storage.path.empty()) {
            storage_failure();
        }
        return storage_windows::open(config);
#else
        storage_failure();
#endif
    case StorageMode::linux_secret_service:
#if defined(__linux__)
        if (config.storage.path.empty()) {
            storage_failure();
        }
        return storage_linux::open(config);
#else
        storage_failure();
#endif
    }
    storage_failure();
}

} // namespace orbit::detail
