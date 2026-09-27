#if defined(__APPLE__)

#include "installed_storage.hpp"

#include "error.hpp"
#include "persistent_codec.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <memory>
#include <openssl/rand.h>
#include <string>
#include <string_view>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace orbit::detail {
namespace {

constexpr char kLeaseName[] = "orbit-storage.lock";
constexpr char kDataName[] = "orbit-storage.bin";
constexpr char kPending = 1;

[[noreturn]] void storage_failure() {
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
    explicit operator bool() const noexcept { return value_ >= 0; }
private:
    int value_ = -1;
};

std::string normalize(std::string_view path) {
    if (path.empty() || path.front() != '/' || path.size() > 4096 ||
        path.find('\0') != std::string_view::npos) storage_failure();
    std::string result = "/";
    std::size_t cursor = 1;
    while (cursor < path.size()) {
        while (cursor < path.size() && path[cursor] == '/') ++cursor;
        const auto start = cursor;
        while (cursor < path.size() && path[cursor] != '/') ++cursor;
        const auto part = path.substr(start, cursor - start);
        if (part.empty() || part == ".") continue;
        if (part == "..") storage_failure();
        if (result.size() > 1) result.push_back('/');
        result.append(part);
    }
    if (result == "/") storage_failure();
    return result;
}

bool same_object(const struct stat& left, const struct stat& right) {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
           (left.st_mode & S_IFMT) == (right.st_mode & S_IFMT);
}

void sync_regular(int fd) {
    if (::fcntl(fd, F_FULLFSYNC) != 0) storage_failure();
}
void sync_directory(int fd) {
    if (::fsync(fd) != 0) storage_failure();
}

struct PinnedDirectory {
    Fd descriptor;
    std::string name;
};

class MacOSInstalledStorage final : public InstalledStorage {
public:
    static std::shared_ptr<InstalledStorage> open(std::string directory) {
        auto result = std::unique_ptr<MacOSInstalledStorage>(new MacOSInstalledStorage());
        try {
            result->pin_directory(directory);
            const auto parent = result->directories_.back().descriptor.get();
            int fd = ::openat(parent, kLeaseName,
                              O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
                              0600);
            result->created_ = fd >= 0;
            if (fd < 0) {
                if (errno != EEXIST) storage_failure();
                fd = ::openat(parent, kLeaseName,
                              O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
            }
            result->lease_ = Fd(fd);
            if (fd < 0 || (result->created_ && ::fchmod(fd, 0600) != 0)) storage_failure();
            if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
                if (errno == EWOULDBLOCK || errno == EAGAIN)
                    throw Error(1, ErrorKind::installation_in_use, "installation_in_use", {});
                storage_failure();
            }
            result->verify_lease(true);
            if (result->created_) {
                sync_regular(fd);
                sync_directory(parent);
            }
            const auto state = result->read_record(true);
            if (result->created_) {
                if (state) corrupt();
                result->initialize_ = true;
            } else {
                if (!state) corrupt();
                result->initialize_ = false;
            }
            return std::shared_ptr<InstalledStorage>(result.release());
        } catch (const Error& error) {
            if (error.kind() == ErrorKind::installation_in_use ||
                error.kind() == ErrorKind::corrupt_state) throw;
            storage_failure();
        } catch (...) {
            storage_failure();
        }
    }

    bool initialization_needed() const noexcept override { return initialize_; }

    void verify() override {
        if (poisoned_) storage_failure();
        try {
            check_directories();
            verify_lease(false);
        } catch (...) { poisoned_ = true; storage_failure(); }
    }

    std::optional<std::string> load() override {
        try {
            auto value = read_record(initialize_);
            if (!value && !initialize_) corrupt();
            return value;
        } catch (const Error& error) {
            poisoned_ = true;
            if (error.kind() == ErrorKind::corrupt_state) throw;
            corrupt();
        } catch (...) { poisoned_ = true; corrupt(); }
    }

    void initialize(std::string_view bytes) override {
        if (poisoned_) storage_failure();
        if (!initialize_) corrupt();
        try {
            write_record(bytes, true);
            initialize_ = false;
        } catch (...) { poisoned_ = true; throw Error(1, ErrorKind::storage, "installation_state_write_failed", {}); }
    }

    void save(std::string_view bytes) override {
        if (poisoned_) storage_failure();
        if (initialize_) corrupt();
        try { write_record(bytes, false); }
        catch (...) { poisoned_ = true; throw Error(1, ErrorKind::storage, "installation_state_write_failed", {}); }
    }

    std::string_view provider() const noexcept override { return "private_file"; }

private:
    MacOSInstalledStorage() = default;

    void pin_directory(std::string_view raw) {
        const auto path = normalize(raw);
        const int root = ::open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (root < 0) storage_failure();
        directories_.push_back({Fd(root), "/"});
        std::size_t cursor = 1;
        while (cursor < path.size()) {
            const auto slash = path.find('/', cursor);
            const auto end = slash == std::string::npos ? path.size() : slash;
            const auto name = path.substr(cursor, end - cursor);
            const int parent = directories_.back().descriptor.get();
            Fd child(::openat(parent, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
            if (!child && errno == ENOENT) {
                if (::mkdirat(parent, name.c_str(), 0700) != 0 && errno != EEXIST) storage_failure();
                sync_directory(parent);
                child = Fd(::openat(parent, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
                if (!child) storage_failure();
                struct stat created{};
                if (::fstat(child.get(), &created) != 0 || ::fchmod(child.get(), 0700) != 0 ||
                    !S_ISDIR(created.st_mode) || created.st_nlink == 0) {
                    storage_failure();
                }
                sync_directory(child.get());
                sync_directory(parent);
            }
            if (!child) storage_failure();
            directories_.push_back({std::move(child), name});
            if (slash == std::string::npos) break;
            cursor = slash + 1;
        }
        check_directories();
    }

    void check_directories() const {
        if (directories_.size() < 2) storage_failure();
        for (std::size_t i = 0; i < directories_.size(); ++i) {
            struct stat held{};
            if (::fstat(directories_[i].descriptor.get(), &held) != 0 ||
                !S_ISDIR(held.st_mode) || held.st_nlink == 0) storage_failure();
            if (i > 0) {
                struct stat named{};
                if (::fstatat(directories_[i - 1].descriptor.get(), directories_[i].name.c_str(),
                              &named, AT_SYMLINK_NOFOLLOW) != 0 || !same_object(held, named))
                    storage_failure();
            }
            if (i + 1 == directories_.size() &&
                (held.st_uid != ::geteuid() || (held.st_mode & 07777) != 0700)) storage_failure();
        }
    }

    static void check_private_file(const struct stat& value, std::size_t expected_size,
                                   bool exact_size = true) {
        if (!S_ISREG(value.st_mode) || value.st_uid != ::geteuid() ||
            (value.st_mode & 07777) != 0600 || value.st_nlink != 1 ||
            value.st_size < 0 || (exact_size && static_cast<std::size_t>(value.st_size) != expected_size))
            storage_failure();
    }

    void verify_lease(bool permit_pending) const {
        check_directories();
        if (!lease_) storage_failure();
        struct stat held{}, named{};
        if (::fstat(lease_.get(), &held) != 0 ||
            ::fstatat(directories_.back().descriptor.get(), kLeaseName, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
            !same_object(held, named)) storage_failure();
        if (held.st_size == 1 && permit_pending) {
            check_private_file(held, 1);
            char marker = 0;
            if (::pread(lease_.get(), &marker, 1, 0) != 1 || marker != kPending) storage_failure();
            return;
        }
        check_private_file(held, 0);
    }

    std::optional<std::string> read_record(bool allow_missing) const {
        verify_lease(false);
        const int parent = directories_.back().descriptor.get();
        Fd file(::openat(parent, kDataName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
        if (!file && errno == ENOENT && allow_missing) return std::nullopt;
        if (!file) storage_failure();
        struct stat held{}, named{};
        if (::fstat(file.get(), &held) != 0) storage_failure();
        check_private_file(held, 0, false);
        if (held.st_size <= 0 || static_cast<std::uint64_t>(held.st_size) > persistent_codec::max_plaintext ||
            ::fstatat(parent, kDataName, &named, AT_SYMLINK_NOFOLLOW) != 0 || !same_object(held, named))
            storage_failure();
        std::string bytes(static_cast<std::size_t>(held.st_size), '\0');
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            const auto count = ::pread(file.get(), bytes.data() + offset, bytes.size() - offset,
                                       static_cast<off_t>(offset));
            if (count < 0) { if (errno == EINTR) continue; storage_failure(); }
            if (count == 0) storage_failure();
            offset += static_cast<std::size_t>(count);
        }
        struct stat after{};
        if (::fstatat(parent, kDataName, &after, AT_SYMLINK_NOFOLLOW) != 0 || !same_object(held, after))
            storage_failure();
        return bytes;
    }

    void write_record(std::string_view bytes, bool allow_missing) {
        if (bytes.empty() || bytes.size() > persistent_codec::max_plaintext) storage_failure();
        auto prior = read_record(allow_missing);
        if (prior) std::fill(prior->begin(), prior->end(), '\0');
        verify_lease(false);
        if (::pwrite(lease_.get(), &kPending, 1, 0) != 1 || ::ftruncate(lease_.get(), 1) != 0) storage_failure();
        sync_regular(lease_.get());
        verify_lease(true);

        std::array<unsigned char, 16> random{};
        if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) storage_failure();
        static constexpr char hex[] = "0123456789abcdef";
        std::string temporary = "orbit-storage.";
        for (const auto byte : random) { temporary.push_back(hex[byte >> 4]); temporary.push_back(hex[byte & 15]); }
        temporary += ".tmp";
        const int parent = directories_.back().descriptor.get();
        Fd file(::openat(parent, temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (!file || ::fchmod(file.get(), 0600) != 0) storage_failure();
        try {
            std::size_t offset = 0;
            while (offset < bytes.size()) {
                const auto count = ::write(file.get(), bytes.data() + offset, bytes.size() - offset);
                if (count < 0) { if (errno == EINTR) continue; storage_failure(); }
                if (count == 0) storage_failure();
                offset += static_cast<std::size_t>(count);
            }
            sync_regular(file.get());
            verify_lease(true);
            struct stat held{}, named{};
            if (::fstat(file.get(), &held) != 0 || ::fstatat(parent, temporary.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
                !same_object(held, named) || !S_ISREG(held.st_mode) || held.st_uid != ::geteuid() ||
                held.st_nlink != 1 || (held.st_mode & 07777) != 0600 ||
                held.st_size != static_cast<off_t>(bytes.size()) ||
                ::renameat(parent, temporary.c_str(), parent, kDataName) != 0) storage_failure();
            sync_directory(parent);
            try {
                if (::ftruncate(lease_.get(), 0) != 0) storage_failure();
                sync_regular(lease_.get());
                verify_lease(false);
            } catch (...) {
                (void)::pwrite(lease_.get(), &kPending, 1, 0);
                (void)::ftruncate(lease_.get(), 1);
                (void)::fcntl(lease_.get(), F_FULLFSYNC);
                throw;
            }
        } catch (...) {
            (void)::unlinkat(parent, temporary.c_str(), 0);
            throw;
        }
        (void)::unlinkat(parent, temporary.c_str(), 0);
    }

    std::vector<PinnedDirectory> directories_;
    Fd lease_;
    bool created_ = false;
    bool initialize_ = false;
    bool poisoned_ = false;
};

} // namespace

std::shared_ptr<InstalledStorage> open_macos_installed_storage(std::string directory) {
    return MacOSInstalledStorage::open(std::move(directory));
}

} // namespace orbit::detail

#endif
