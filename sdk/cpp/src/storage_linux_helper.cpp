#include "storage_linux_internal.hpp"

#if defined(__linux__)
#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace orbit::detail::storage_linux_internal {
namespace {

constexpr std::size_t kMaximumBase64 = 5464;
constexpr std::size_t kMaximumStdout = kMaximumBase64 + 1;
constexpr std::size_t kMaximumStderr = 4096;
constexpr std::size_t kMaximumStdin = kMaximumBase64;

[[noreturn]] void storage_failure() {
    throw Error(1, ErrorKind::storage, "storage", {});
}

class Fd {
public:
    Fd() = default;
    explicit Fd(int fd) : fd_(fd) {}
    ~Fd() { reset(); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
    Fd& operator=(Fd&& other) noexcept {
        if (this != &other) {
            reset();
            fd_ = std::exchange(other.fd_, -1);
        }
        return *this;
    }
    int get() const { return fd_; }
    explicit operator bool() const { return fd_ >= 0; }
    void reset(int fd = -1) {
        if (fd_ >= 0) {
            (void)::close(fd_);
        }
        fd_ = fd;
    }

private:
    int fd_ = -1;
};

struct Pipes {
    Fd input_read;
    Fd input_write;
    Fd output_read;
    Fd output_write;
    Fd error_read;
    Fd error_write;
};

void make_pipe(Fd& read_end, Fd& write_end) {
    int descriptors[2];
    if (::pipe2(descriptors, O_CLOEXEC) != 0) {
        storage_failure();
    }
    for (auto& descriptor : descriptors) {
        if (descriptor <= STDERR_FILENO) {
            const int moved = ::fcntl(descriptor, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
            const int saved_errno = errno;
            (void)::close(descriptor);
            if (moved < 0) {
                (void)::close(descriptors[0]);
                (void)::close(descriptors[1]);
                errno = saved_errno;
                storage_failure();
            }
            descriptor = moved;
        }
    }
    read_end.reset(descriptors[0]);
    write_end.reset(descriptors[1]);
}

void set_nonblocking(int fd) {
    const int flags = ::fcntl(fd, F_GETFL);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        storage_failure();
    }
}

class BlockSigpipe {
public:
    BlockSigpipe() {
        sigemptyset(&set_);
        sigaddset(&set_, SIGPIPE);
        if (pthread_sigmask(SIG_BLOCK, &set_, &previous_) != 0) {
            storage_failure();
        }
        active_ = true;
    }
    ~BlockSigpipe() {
        if (!active_) {
            return;
        }
        if (sigismember(&previous_, SIGPIPE) == 0) {
            sigset_t pending{};
            if (sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1) {
                timespec immediate{};
                while (::sigtimedwait(&set_, nullptr, &immediate) < 0 && errno == EINTR) {}
            }
        }
        (void)pthread_sigmask(SIG_SETMASK, &previous_, nullptr);
    }
    BlockSigpipe(const BlockSigpipe&) = delete;
    BlockSigpipe& operator=(const BlockSigpipe&) = delete;

private:
    sigset_t set_{};
    sigset_t previous_{};
    bool active_ = false;
};

struct Child {
    pid_t pid = -1;
    bool group_owned = false;
    bool reaped = false;
    int status = 0;
    ~Child() {
        if (pid < 0 || reaped) {
            return;
        }
        if (group_owned) {
            (void)::kill(-pid, SIGKILL);
        }
        (void)::kill(pid, SIGKILL);
        while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    }
};

struct Output {
    int status = 0;
    std::string standard_output;
    std::string standard_error;
};

void drain_fd(Fd& fd, std::string& destination, std::size_t maximum,
              bool& eof) {
    std::array<char, 1024> buffer{};
    while (fd) {
        const auto count = ::read(fd.get(), buffer.data(),
                                 std::min(buffer.size(), maximum - destination.size() + 1));
        if (count == 0) {
            eof = true;
            fd.reset();
            return;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            storage_failure();
        }
        if (destination.size() + static_cast<std::size_t>(count) > maximum) {
            storage_failure();
        }
        destination.append(buffer.data(), static_cast<std::size_t>(count));
    }
    eof = true;
}

Output run(std::string_view executable, const std::vector<std::string>& arguments,
           std::string_view input, std::chrono::milliseconds deadline) {
    if (executable.empty() || executable.front() != '/' ||
        executable.find('\0') != std::string_view::npos ||
        input.size() > kMaximumStdin || deadline.count() < 0) {
        storage_failure();
    }
    Pipes pipes;
    make_pipe(pipes.input_read, pipes.input_write);
    make_pipe(pipes.output_read, pipes.output_write);
    make_pipe(pipes.error_read, pipes.error_write);

    std::vector<std::string> owned_arguments;
    owned_arguments.reserve(arguments.size() + 1);
    owned_arguments.emplace_back(executable);
    owned_arguments.insert(owned_arguments.end(), arguments.begin(), arguments.end());
    std::vector<char*> argv;
    argv.reserve(owned_arguments.size() + 1);
    for (auto& argument : owned_arguments) {
        argv.push_back(argument.data());
    }
    argv.push_back(nullptr);

    const auto started = std::chrono::steady_clock::now();
    Child child;
    child.pid = ::fork();
    if (child.pid < 0) {
        storage_failure();
    }
    if (child.pid == 0) {
        if (::setpgid(0, 0) != 0) {
            _exit(127);
        }
        if (::dup2(pipes.input_read.get(), STDIN_FILENO) < 0 ||
            ::dup2(pipes.output_write.get(), STDOUT_FILENO) < 0 ||
            ::dup2(pipes.error_write.get(), STDERR_FILENO) < 0) {
            _exit(127);
        }
        pipes.input_read.reset();
        pipes.input_write.reset();
        pipes.output_read.reset();
        pipes.output_write.reset();
        pipes.error_read.reset();
        pipes.error_write.reset();
        ::execv(owned_arguments[0].c_str(), argv.data());
        _exit(127);
    }
    if (::setpgid(child.pid, child.pid) == 0 || errno == EACCES ||
        ::getpgid(child.pid) == child.pid) {
        child.group_owned = true;
    }
    pipes.input_read.reset();
    pipes.output_write.reset();
    pipes.error_write.reset();
    set_nonblocking(pipes.input_write.get());
    set_nonblocking(pipes.output_read.get());
    set_nonblocking(pipes.error_read.get());

    Output output;
    std::size_t input_offset = 0;
    bool output_eof = false;
    bool error_eof = false;
    bool input_closed = false;
    BlockSigpipe sigpipe;
    while (!child.reaped || !output_eof || !error_eof) {
        const auto now = std::chrono::steady_clock::now();
        if (now - started >= deadline) {
            storage_failure();
        }
        if (input_offset == input.size() && !input_closed) {
            pipes.input_write.reset();
            input_closed = true;
        }
        std::array<pollfd, 3> descriptors{};
        nfds_t descriptor_count = 0;
        if (pipes.input_write) {
            descriptors[descriptor_count++] = pollfd{
                pipes.input_write.get(), POLLOUT, 0};
        }
        if (pipes.output_read) {
            descriptors[descriptor_count++] = pollfd{
                pipes.output_read.get(), POLLIN | POLLHUP, 0};
        }
        if (pipes.error_read) {
            descriptors[descriptor_count++] = pollfd{
                pipes.error_read.get(), POLLIN | POLLHUP, 0};
        }
        const auto remaining = deadline -
            std::chrono::duration_cast<std::chrono::milliseconds>(now - started);
        const auto timeout = static_cast<int>(std::clamp<std::int64_t>(
            remaining.count(), 1, 50));
        const int ready = ::poll(descriptors.data(), descriptor_count, timeout);
        if (ready < 0 && errno != EINTR) {
            storage_failure();
        }
        if (pipes.input_write && input_offset < input.size()) {
            const auto count = ::write(pipes.input_write.get(),
                                       input.data() + input_offset,
                                       input.size() - input_offset);
            if (count > 0) {
                input_offset += static_cast<std::size_t>(count);
            } else if (count < 0 && errno != EINTR && errno != EAGAIN &&
                       errno != EWOULDBLOCK) {
                storage_failure();
            } else if (count == 0) {
                storage_failure();
            }
        }
        drain_fd(pipes.output_read, output.standard_output, kMaximumStdout, output_eof);
        drain_fd(pipes.error_read, output.standard_error, kMaximumStderr, error_eof);
        siginfo_t child_info{};
        if (::waitid(P_PID, static_cast<id_t>(child.pid), &child_info,
                     WEXITED | WNOHANG | WNOWAIT) != 0 && errno != EINTR) {
            storage_failure();
        }
        if (child_info.si_pid != 0 && output_eof && error_eof) {
            if (child.group_owned) {
                (void)::kill(-child.pid, SIGKILL);
            }
            const auto waited = ::waitpid(child.pid, &child.status, 0);
            if (waited != child.pid) {
                storage_failure();
            }
            child.reaped = true;
            if (!WIFEXITED(child.status)) {
                storage_failure();
            }
        }
    }
    if (input_offset != input.size()) {
        storage_failure();
    }
    return Output{child.status, std::move(output.standard_output),
                  std::move(output.standard_error)};
}

std::vector<std::string> lookup_arguments(std::string_view scope) {
    return {"lookup", "application", "orbit-sdk", "sdk", "rust", "scope",
            std::string(scope)};
}

std::vector<std::string> store_arguments(std::string_view scope) {
    return {"store", "--label=Orbit Rust SDK activation", "--collection=default",
            "application", "orbit-sdk", "sdk", "rust", "scope", std::string(scope)};
}

} // namespace

std::optional<std::string> lookup(std::string_view executable,
                                  std::string_view scope,
                                  std::chrono::milliseconds deadline) {
    auto output = run(executable, lookup_arguments(scope), {}, deadline);
    if (!output.standard_error.empty()) {
        storage_failure();
    }
    if (WIFEXITED(output.status) && WEXITSTATUS(output.status) == 0) {
        return output.standard_output;
    }
    if (WIFEXITED(output.status) && WEXITSTATUS(output.status) == 1 &&
        output.standard_output.empty()) {
        return std::nullopt;
    }
    storage_failure();
}

void store(std::string_view executable, std::string_view scope,
           std::string_view record, std::chrono::milliseconds deadline) {
    if (record.size() > kMaximumBase64) {
        storage_failure();
    }
    const auto output = run(executable, store_arguments(scope), record, deadline);
    if (!WIFEXITED(output.status) || WEXITSTATUS(output.status) != 0 ||
        !output.standard_output.empty() || !output.standard_error.empty()) {
        storage_failure();
    }
}

} // namespace orbit::detail::storage_linux_internal

#else

namespace orbit::detail::storage_linux_internal {
namespace {
[[noreturn]] void storage_failure() {
    throw Error(1, ErrorKind::storage, "storage", {});
}
} // namespace

std::optional<std::string> lookup(std::string_view, std::string_view,
                                  std::chrono::milliseconds) {
    storage_failure();
}

void store(std::string_view, std::string_view, std::string_view,
           std::chrono::milliseconds) {
    storage_failure();
}

} // namespace orbit::detail::storage_linux_internal

#endif
