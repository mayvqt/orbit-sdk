#include "storage_linux_internal.hpp"

#include "platform.hpp"

#include <memory>
#include <array>
#include <cstdint>
#include <string>
#include <utility>

#if defined(__linux__)
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#endif

namespace orbit::detail::storage_linux_internal {
namespace {

[[noreturn]] void storage_failure() {
    throw Error(1, ErrorKind::storage, "storage", {});
}

#if defined(__linux__)

constexpr char kLeaseName[] = "orbit-storage.lock";
constexpr char kPending[] = {1};

class Fd {
public:
    Fd() = default;
    explicit Fd(int value) : value_(value) {}
    ~Fd() { reset(); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : value_(std::exchange(other.value_, -1)) {}
    Fd& operator=(Fd&& other) noexcept {
        if (this != &other) {
            reset();
            value_ = std::exchange(other.value_, -1);
        }
        return *this;
    }
    int get() const { return value_; }
    explicit operator bool() const { return value_ >= 0; }
    void reset(int value = -1) {
        if (value_ >= 0) {
            (void)::close(value_);
        }
        value_ = value;
    }

private:
    int value_ = -1;
};

bool valid_utf8(std::string_view value) {
    std::size_t cursor = 0;
    while (cursor < value.size()) {
        const auto lead = static_cast<unsigned char>(value[cursor]);
        if (lead <= 0x7f) {
            ++cursor;
            continue;
        }
        std::size_t width = 0;
        std::uint32_t codepoint = 0;
        if (lead >= 0xc2 && lead <= 0xdf) {
            width = 2;
            codepoint = lead & 0x1f;
        } else if (lead >= 0xe0 && lead <= 0xef) {
            width = 3;
            codepoint = lead & 0x0f;
        } else if (lead >= 0xf0 && lead <= 0xf4) {
            width = 4;
            codepoint = lead & 0x07;
        } else {
            return false;
        }
        if (width > value.size() - cursor) {
            return false;
        }
        for (std::size_t i = 1; i < width; ++i) {
            const auto continuation = static_cast<unsigned char>(value[cursor + i]);
            if ((continuation & 0xc0) != 0x80) {
                return false;
            }
            codepoint = (codepoint << 6) | (continuation & 0x3f);
        }
        if ((width == 2 && codepoint < 0x80) ||
            (width == 3 && codepoint < 0x800) ||
            (width == 4 && codepoint < 0x10000) ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff) {
            return false;
        }
        cursor += width;
    }
    return true;
}

std::string normalize(std::string_view path) {
    if (path.empty() || path.front() != '/' ||
        path.find('\0') != std::string_view::npos || !valid_utf8(path)) {
        storage_failure();
    }
    std::string output = "/";
    std::size_t cursor = 1;
    while (cursor < path.size()) {
        while (cursor < path.size() && path[cursor] == '/') {
            ++cursor;
        }
        const auto start = cursor;
        while (cursor < path.size() && path[cursor] != '/') {
            ++cursor;
        }
        const auto component = path.substr(start, cursor - start);
        if (component.empty() || component == ".") {
            continue;
        }
        if (component == "..") {
            storage_failure();
        }
        if (output.size() > 1) {
            output.push_back('/');
        }
        output.append(component);
    }
    return output;
}

bool same_inode(const struct stat& left, const struct stat& right) {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino;
}

bool private_file(const struct stat& info) {
    return info.st_uid == geteuid() && (info.st_mode & 0077) == 0;
}

void checked_stat(int fd, const char* path, bool directory,
                  bool require_private, std::size_t marker_size,
                  std::string_view expected_marker) {
    struct stat descriptor{};
    struct stat named{};
    if (::fstat(fd, &descriptor) != 0 || ::lstat(path, &named) != 0 ||
        !same_inode(descriptor, named) || descriptor.st_nlink == 0 ||
        named.st_nlink == 0 ||
        (directory ? (!S_ISDIR(descriptor.st_mode) || !S_ISDIR(named.st_mode))
                   : (!S_ISREG(descriptor.st_mode) || !S_ISREG(named.st_mode))) ||
        (require_private &&
         (!private_file(descriptor) || !private_file(named)))) {
        storage_failure();
    }
    if (!directory) {
        if (descriptor.st_nlink != 1 || named.st_nlink != 1 ||
            descriptor.st_size != static_cast<off_t>(marker_size) ||
            named.st_size != static_cast<off_t>(marker_size)) {
            storage_failure();
        }
        std::array<char, 2> marker{};
        const auto read = ::pread(fd, marker.data(), marker.size(), 0);
        if (read < 0 || static_cast<std::size_t>(read) != expected_marker.size() ||
            std::string_view(marker.data(), static_cast<std::size_t>(read)) !=
                expected_marker) {
            storage_failure();
        }
    }
}

void write_pending(int fd) {
    if (::pwrite(fd, kPending, sizeof(kPending), 0) != sizeof(kPending) ||
        ::ftruncate(fd, sizeof(kPending)) != 0 || ::fsync(fd) != 0) {
        storage_failure();
    }
}

#endif

} // namespace

struct Lease::State {
#if defined(__linux__)
    std::vector<Fd> directories;
    std::vector<std::string> directory_paths;
    Fd file;
    std::string normalized_directory;
    std::string lease_path;
    bool was_created = false;

    ~State() {
        if (file) {
            (void)::flock(file.get(), LOCK_UN);
        }
    }
#endif
};

Lease::Lease() = default;
Lease::Lease(std::unique_ptr<State> state) : state_(std::move(state)) {}
Lease::~Lease() = default;
Lease::Lease(Lease&&) noexcept = default;
Lease& Lease::operator=(Lease&&) noexcept = default;

Lease Lease::open(std::string_view directory) {
#if defined(__linux__)
    auto state = std::make_unique<State>();
    state->normalized_directory = normalize(directory);
    int root = ::open("/", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) {
        storage_failure();
    }
    state->directories.emplace_back(root);
    state->directory_paths.emplace_back("/");
    std::size_t cursor = 1;
    std::string current = "/";
    while (cursor < state->normalized_directory.size()) {
        const auto separator = state->normalized_directory.find('/', cursor);
        const auto end = separator == std::string::npos
            ? state->normalized_directory.size() : separator;
        const auto component = state->normalized_directory.substr(cursor, end - cursor);
        const int parent = state->directories.back().get();
        const int fd = ::openat(parent, component.c_str(),
                                O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            storage_failure();
        }
        if (current.size() > 1) {
            current.push_back('/');
        }
        current.append(component);
        state->directories.emplace_back(fd);
        state->directory_paths.push_back(current);
        if (separator == std::string::npos) {
            break;
        }
        cursor = separator + 1;
    }
    state->lease_path = state->normalized_directory + "/" + kLeaseName;
    struct stat directory_info{};
    if (::fstat(state->directories.back().get(), &directory_info) != 0 ||
        !S_ISDIR(directory_info.st_mode) || !private_file(directory_info) ||
        directory_info.st_nlink == 0) {
        storage_failure();
    }

    constexpr int base_flags = O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK;
    int lease_fd = ::openat(state->directories.back().get(), kLeaseName,
                            base_flags | O_CREAT | O_EXCL, 0600);
    if (lease_fd >= 0) {
        state->was_created = true;
    } else if (errno == EEXIST) {
        lease_fd = ::openat(state->directories.back().get(), kLeaseName, base_flags);
    }
    if (lease_fd < 0) {
        storage_failure();
    }
    state->file.reset(lease_fd);
    struct stat lease_info{};
    if (::fstat(lease_fd, &lease_info) != 0 || !S_ISREG(lease_info.st_mode) ||
        !private_file(lease_info) || lease_info.st_nlink != 1 ||
        ::flock(lease_fd, LOCK_EX | LOCK_NB) != 0) {
        storage_failure();
    }
    Lease result(std::move(state));
    result.verify();
    if (result.created()) {
        if (::fsync(result.state_->file.get()) != 0) {
            storage_failure();
        }
        const int directory_fd = ::openat(result.state_->directories.back().get(), ".",
                                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (directory_fd < 0) {
            storage_failure();
        }
        Fd parent_directory(directory_fd);
        if (::fsync(parent_directory.get()) != 0) {
            storage_failure();
        }
        result.verify();
    }
    return result;
#else
    (void)directory;
    storage_failure();
#endif
}

bool Lease::created() const {
#if defined(__linux__)
    return state_ && state_->was_created;
#else
    return false;
#endif
}

const std::string& Lease::directory() const {
#if defined(__linux__)
    if (!state_) {
        storage_failure();
    }
    return state_->normalized_directory;
#else
    storage_failure();
#endif
}

void Lease::verify() const {
#if defined(__linux__)
    if (!state_ || state_->directories.empty() || !state_->file) {
        storage_failure();
    }
    for (std::size_t i = 0; i < state_->directories.size(); ++i) {
        checked_stat(state_->directories[i].get(), state_->directory_paths[i].c_str(),
                     true, i + 1 == state_->directories.size(), 0, {});
    }
    checked_stat(state_->file.get(), state_->lease_path.c_str(), false, true, 0, {});
#else
    storage_failure();
#endif
}

void Lease::begin_write() {
#if defined(__linux__)
    verify();
    write_pending(state_->file.get());
    checked_stat(state_->file.get(), state_->lease_path.c_str(), false, true,
                 sizeof(kPending), std::string_view(kPending, sizeof(kPending)));
#else
    storage_failure();
#endif
}

void Lease::complete_write() {
#if defined(__linux__)
    checked_stat(state_->file.get(), state_->lease_path.c_str(), false, true,
                 sizeof(kPending), std::string_view(kPending, sizeof(kPending)));
    if (::ftruncate(state_->file.get(), 0) != 0 ||
        ::fsync(state_->file.get()) != 0) {
        try {
            write_pending(state_->file.get());
        } catch (...) {
        }
        storage_failure();
    }
    try {
        verify();
    } catch (...) {
        try {
            write_pending(state_->file.get());
        } catch (...) {
        }
        storage_failure();
    }
#else
    storage_failure();
#endif
}

} // namespace orbit::detail::storage_linux_internal
