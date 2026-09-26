#if defined(__linux__)

#include "installed_storage.hpp"

#include "error.hpp"
#include "storage_linux_internal.hpp"

#include <cerrno>
#include <fcntl.h>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace orbit::detail {
namespace {

[[noreturn]] void unavailable() {
    throw Error(1, ErrorKind::storage, "installation_storage_unavailable", {});
}
[[noreturn]] void corrupt() {
    throw Error(1, ErrorKind::corrupt_state, "installation_state_corrupt", {});
}

class Fd {
public:
    explicit Fd(int value = -1) : value_(value) {}
    ~Fd() { if (value_ >= 0) (void)::close(value_); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : value_(std::exchange(other.value_, -1)) {}
    Fd& operator=(Fd&& other) noexcept {
        if (this != &other) {
            if (value_ >= 0) (void)::close(value_);
            value_ = std::exchange(other.value_, -1);
        }
        return *this;
    }
    int get() const noexcept { return value_; }
private:
    int value_;
};

std::string normalize(std::string_view input) {
    if (input.empty() || input.front() != '/' || input.size() > 4096 ||
        input.find('\0') != std::string_view::npos) unavailable();
    std::string result = "/";
    std::size_t cursor = 1;
    while (cursor < input.size()) {
        while (cursor < input.size() && input[cursor] == '/') ++cursor;
        const auto start = cursor;
        while (cursor < input.size() && input[cursor] != '/') ++cursor;
        const auto part = input.substr(start, cursor - start);
        if (part.empty() || part == ".") continue;
        if (part == "..") unavailable();
        if (result.size() > 1) result.push_back('/');
        result.append(part);
    }
    if (result == "/") unavailable();
    return result;
}

bool private_directory(const struct stat& value) {
    return S_ISDIR(value.st_mode) && value.st_uid == ::geteuid() &&
           (value.st_mode & 0077) == 0 && value.st_nlink != 0;
}

void sync_parent(int fd) {
    if (::fsync(fd) != 0) unavailable();
}

std::string create_private_directory_tree(std::string_view path) {
    const auto normalized = normalize(path);
    Fd current(::open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (current.get() < 0) unavailable();
    std::size_t cursor = 1;
    std::string accumulated = "/";
    while (cursor < normalized.size()) {
        const auto slash = normalized.find('/', cursor);
        const auto end = slash == std::string::npos ? normalized.size() : slash;
        const auto component = normalized.substr(cursor, end - cursor);
        int next = ::openat(current.get(), component.c_str(),
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 && errno == ENOENT) {
            if (::mkdirat(current.get(), component.c_str(), 0700) == 0) {
                sync_parent(current.get());
            } else if (errno != EEXIST) {
                unavailable();
            }
            next = ::openat(current.get(), component.c_str(),
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        if (next < 0) unavailable();
        Fd child(next);
        struct stat info{};
        if (::fstat(next, &info) != 0 || !S_ISDIR(info.st_mode) || info.st_nlink == 0) {
            unavailable();
        }
        if (accumulated.size() > 1) accumulated.push_back('/');
        accumulated.append(component);
        if (slash == std::string::npos) {
            if (!private_directory(info)) unavailable();
        }
        current = std::move(child);
        if (slash == std::string::npos) break;
        cursor = slash + 1;
    }
    return normalized;
}

class LinuxInstalledStorage final : public InstalledStorage {
public:
    static std::shared_ptr<InstalledStorage> open(std::string directory) {
        const auto normalized = create_private_directory_tree(directory);
        storage_linux_internal::Lease lease;
        try {
            lease = storage_linux_internal::Lease::open(normalized, true);
            const auto state = lease.read_installed_record();
            if (lease.created()) {
                if (state) corrupt();
                return std::shared_ptr<InstalledStorage>(
                    new LinuxInstalledStorage(std::move(lease), true));
            }
            if (!state) corrupt();
            return std::shared_ptr<InstalledStorage>(
                new LinuxInstalledStorage(std::move(lease), false));
        } catch (const Error& error) {
            if (error.kind() == ErrorKind::installation_in_use ||
                error.kind() == ErrorKind::corrupt_state) throw;
            throw Error(1, ErrorKind::storage, "installation_storage_unavailable", {});
        } catch (...) {
            unavailable();
        }
    }

    bool initialization_needed() const noexcept override { return initialize_; }

    std::optional<std::string> load() override {
        try {
            const auto value = lease_.read_installed_record();
            if (!value && !initialize_) corrupt();
            return value;
        } catch (const Error& error) {
            if (error.kind() == ErrorKind::corrupt_state) throw;
            throw Error(1, ErrorKind::corrupt_state, "installation_state_corrupt", {});
        } catch (...) {
            corrupt();
        }
    }

    void initialize(std::string_view bytes) override {
        if (!initialize_) corrupt();
        try {
            lease_.write_installed_record(bytes, true);
            initialize_ = false;
        } catch (...) {
            throw Error(1, ErrorKind::storage, "installation_state_write_failed", {});
        }
    }

    void save(std::string_view bytes) override {
        if (initialize_) corrupt();
        try {
            lease_.write_installed_record(bytes, false);
        } catch (...) {
            throw Error(1, ErrorKind::storage, "installation_state_write_failed", {});
        }
    }

    std::string_view provider() const noexcept override { return "private_file"; }

private:
    LinuxInstalledStorage(storage_linux_internal::Lease lease, bool initialize)
        : lease_(std::move(lease)), initialize_(initialize) {}

    storage_linux_internal::Lease lease_;
    bool initialize_ = false;
};

} // namespace

std::shared_ptr<InstalledStorage> open_linux_installed_storage(std::string directory) {
    return LinuxInstalledStorage::open(std::move(directory));
}

} // namespace orbit::detail

#endif
