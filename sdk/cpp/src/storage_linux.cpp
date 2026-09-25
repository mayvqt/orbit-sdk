#include "storage_linux.hpp"

#include "storage_codec.hpp"
#include "storage_linux_internal.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

namespace orbit::detail::storage_linux {
namespace {

[[noreturn]] void storage_failure() {
    throw Error(1, ErrorKind::storage, "storage", {});
}

#if defined(__linux__)

constexpr std::size_t kMaximumRecord = 4096;
constexpr std::size_t kMaximumBase64 = 5464;
constexpr std::size_t kMaximumStdout = kMaximumBase64 + 1;

void hash_update(EVP_MD_CTX* context, const void* bytes, std::size_t length) {
    if (EVP_DigestUpdate(context, bytes, length) != 1) {
        storage_failure();
    }
}

void append_u32(std::string& output, std::uint32_t value) {
    output.push_back(static_cast<char>((value >> 24) & 0xff));
    output.push_back(static_cast<char>((value >> 16) & 0xff));
    output.push_back(static_cast<char>((value >> 8) & 0xff));
    output.push_back(static_cast<char>(value & 0xff));
}

std::string hex_lower(const unsigned char* bytes, std::size_t length) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(length * 2);
    for (std::size_t i = 0; i < length; ++i) {
        output.push_back(digits[bytes[i] >> 4]);
        output.push_back(digits[bytes[i] & 15]);
    }
    return output;
}

std::string item_scope(const Config& config,
                       const std::array<unsigned char, 32>& entropy,
                       std::string_view directory) {
    if (directory.size() > UINT32_MAX) {
        storage_failure();
    }
    EVP_MD_CTX* raw = EVP_MD_CTX_new();
    if (raw == nullptr) {
        storage_failure();
    }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(raw,
                                                                   EVP_MD_CTX_free);
    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        storage_failure();
    }
    static constexpr char domain[] = "orbit.sdk.secret-service.v1\0";
    hash_update(context.get(), domain, sizeof(domain) - 1);
    std::string framed;
    append_u32(framed, 4);
    framed.append("rust", 4);
    framed.append(reinterpret_cast<const char*>(entropy.data()), entropy.size());
    append_u32(framed, static_cast<std::uint32_t>(directory.size()));
    framed.append(directory);
    hash_update(context.get(), framed.data(), framed.size());
    std::array<unsigned char, 32> digest{};
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &length) != 1 ||
        length != digest.size()) {
        storage_failure();
    }
    (void)config;
    return hex_lower(digest.data(), digest.size());
}

std::string base64_encode(std::string_view input) {
    if (input.empty() || input.size() > kMaximumRecord) {
        storage_failure();
    }
    const auto maximum = 4 * ((input.size() + 2) / 3);
    std::string output(maximum, '\0');
    const int length = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(output.data()),
        reinterpret_cast<const unsigned char*>(input.data()),
        static_cast<int>(input.size()));
    if (length < 0 || static_cast<std::size_t>(length) != maximum ||
        maximum > kMaximumBase64) {
        storage_failure();
    }
    return output;
}

std::string base64_decode_canonical(std::string_view output) {
    if (output.size() > kMaximumStdout) {
        storage_failure();
    }
    if (!output.empty() && output.back() == '\n') {
        output.remove_suffix(1);
    }
    if (output.empty() || output.size() > kMaximumBase64 ||
        output.size() % 4 != 0) {
        storage_failure();
    }
    for (std::size_t i = 0; i < output.size(); ++i) {
        const auto c = static_cast<unsigned char>(output[i]);
        const bool alphabet = (c >= 'A' && c <= 'Z') ||
                              (c >= 'a' && c <= 'z') ||
                              (c >= '0' && c <= '9') || c == '+' || c == '/';
        if (!alphabet && !(c == '=' && i >= output.size() - 2)) {
            storage_failure();
        }
    }
    const auto padding = output.back() == '='
        ? (output.size() >= 2 && output[output.size() - 2] == '=' ? 2U : 1U)
        : 0U;
    if (padding == 1 && output[output.size() - 2] == '=') {
        storage_failure();
    }
    std::string decoded((output.size() / 4) * 3, '\0');
    const int count = EVP_DecodeBlock(
        reinterpret_cast<unsigned char*>(decoded.data()),
        reinterpret_cast<const unsigned char*>(output.data()),
        static_cast<int>(output.size()));
    if (count < 0 || static_cast<std::size_t>(count) < padding) {
        storage_failure();
    }
    decoded.resize(static_cast<std::size_t>(count) - padding);
    if (decoded.size() > kMaximumRecord || base64_encode(decoded) != output) {
        storage_failure();
    }
    return decoded;
}

class SecretServiceStorage final : public CredentialStorage {
public:
    SecretServiceStorage(const Config& config, std::string helper,
                         std::chrono::milliseconds deadline,
                         storage_linux_internal::Lease lease,
                         std::array<unsigned char, 32> entropy,
                         std::string scope)
        : config_(config), helper_(std::move(helper)), deadline_(deadline),
          lease_(std::move(lease)), entropy_(entropy), scope_(std::move(scope)) {}

    static std::shared_ptr<CredentialStorage> open(
        const Config& config, std::string_view helper,
        std::chrono::milliseconds deadline) {
        (void)storage_codec::encode(config, 0, std::nullopt);
        auto lease = storage_linux_internal::Lease::open(config.storage.path);
        const auto entropy = storage_codec::entropy(config);
        auto scope = item_scope(config, entropy, lease.directory());
        auto state = std::shared_ptr<SecretServiceStorage>(new SecretServiceStorage(
            config, std::string(helper), deadline, std::move(lease), entropy,
            std::move(scope)));
        const auto stored = storage_linux_internal::lookup(
            state->helper_, state->scope_, state->deadline_);
        if (stored) {
            const auto decoded = state->decode_item(*stored);
            state->generation_ = decoded.first;
            state->credential_ = decoded.second;
        } else if (state->lease_.created()) {
            state->commit(0, std::nullopt);
        } else {
            storage_failure();
        }
        state->check();
        return state;
    }

    std::uint64_t version() override {
        std::lock_guard<std::mutex> lock(mutex_);
        check();
        return generation_;
    }

    std::pair<std::uint64_t, std::optional<Json::Value>> load() override {
        std::lock_guard<std::mutex> lock(mutex_);
        check();
        return {generation_, credential_};
    }

    void save(std::uint64_t expected_version,
              const Json::Value& credential) override {
        std::lock_guard<std::mutex> lock(mutex_);
        check();
        if (expected_version != generation_) {
            throw Error(1, ErrorKind::stale_response, "stale_response", {});
        }
        commit(generation_, credential);
    }

    std::uint64_t invalidate() override {
        std::lock_guard<std::mutex> lock(mutex_);
        check();
        if (generation_ == storage_codec::max_generation) {
            poison();
            storage_failure();
        }
        const auto next = generation_ + 1;
        commit(next, std::nullopt);
        return next;
    }

private:
    std::pair<std::uint64_t, std::optional<Json::Value>> decode_item(
        std::string_view output) const {
        const auto record = base64_decode_canonical(output);
        return storage_codec::decode(config_, record);
    }

    void check() {
        if (poisoned_) {
            storage_failure();
        }
        try {
            lease_.verify();
        } catch (...) {
            poison();
            storage_failure();
        }
    }

    void poison() {
        poisoned_ = true;
        credential_.reset();
    }

    void commit(std::uint64_t generation,
                const std::optional<Json::Value>& credential) {
        try {
            check();
            const auto record = storage_codec::encode(config_, generation, credential);
            const auto encoded = base64_encode(record);
            lease_.begin_write();
            storage_linux_internal::store(helper_, scope_, encoded, deadline_);
            lease_.complete_write();
            generation_ = generation;
            credential_ = credential;
        } catch (const Error& error) {
            if (error.kind() == ErrorKind::stale_response) {
                throw;
            }
            poison();
            storage_failure();
        } catch (...) {
            poison();
            storage_failure();
        }
    }

    Config config_;
    std::string helper_;
    std::chrono::milliseconds deadline_;
    storage_linux_internal::Lease lease_;
    std::array<unsigned char, 32> entropy_{};
    std::string scope_;
    std::mutex mutex_;
    std::uint64_t generation_ = 0;
    std::optional<Json::Value> credential_;
    bool poisoned_ = false;
};

#endif // __linux__

} // namespace

std::shared_ptr<CredentialStorage> open(const Config& config,
                                        std::string_view helper,
                                        std::chrono::milliseconds deadline) {
#if defined(__linux__)
    return SecretServiceStorage::open(config, helper, deadline);
#else
    (void)config;
    (void)helper;
    (void)deadline;
    storage_failure();
#endif
}

} // namespace orbit::detail::storage_linux
