#include "error.hpp"
#include "online.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <curl/curl.h>
#include <filesystem>
#include <limits>
#include <mutex>
#include <openssl/evp.h>
#ifdef _WIN32
#include <io.h>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace orbit::detail {
namespace {
struct Transfer {
    FILE *file = nullptr;
    EVP_MD_CTX *hash = nullptr;
    const std::atomic_bool &cancelled;
    std::int64_t expected, maximum, received = 0;
    long status = 0;
    std::size_t headers = 0;
    bool invalid = false, io_error = false;
    std::optional<std::int64_t> length;
    std::string location;
    bool encoding_seen = false;
    Transfer(FILE *output, EVP_MD_CTX *digest, const std::atomic_bool &cancel, std::int64_t expected_bytes,
             std::int64_t maximum_bytes)
        : file(output), hash(digest), cancelled(cancel), expected(expected_bytes), maximum(maximum_bytes) {}
};
size_t write_bytes(char *data, size_t size, size_t count, void *context) noexcept {
    auto &t = *static_cast<Transfer *>(context);
    if (t.cancelled.load() || t.status != 200)
        return 0;
    if (size != 0 && count > std::numeric_limits<std::size_t>::max() / size) {
        t.invalid = true;
        return 0;
    }
    const auto bytes = size * count;
    if (bytes > static_cast<std::uint64_t>(t.expected - t.received) ||
        bytes > static_cast<std::uint64_t>(t.maximum - t.received)) {
        t.invalid = true;
        return 0;
    }
    if (EVP_DigestUpdate(t.hash, data, bytes) != 1 || std::fwrite(data, 1, bytes, t.file) != bytes) {
        t.io_error = true;
        return 0;
    }
    t.received += static_cast<std::int64_t>(bytes);
    return bytes;
}
size_t read_headers(char *data, size_t size, size_t count, void *context) noexcept {
    auto &t = *static_cast<Transfer *>(context);
    try {
        if (size != 0 && count > std::numeric_limits<std::size_t>::max() / size) {
            t.invalid = true;
            return 0;
        }
        const auto bytes = size * count;
        if (bytes > 16384 - t.headers) {
            t.invalid = true;
            return 0;
        }
        t.headers += bytes;
        std::string_view line(data, bytes);
        if (line.substr(0, 5) == "HTTP/") {
            const auto space = line.find(' ');
            if (space == std::string_view::npos || space + 4 > line.size()) {
                t.invalid = true;
                return 0;
            }
            t.status = 0;
            for (std::size_t i = space + 1; i < space + 4; ++i) {
                if (line[i] < '0' || line[i] > '9') {
                    t.invalid = true;
                    return 0;
                }
                t.status = t.status * 10 + line[i] - '0';
            }
            t.length.reset();
            t.location.clear();
            t.encoding_seen = false;
        }
        const auto colon = line.find(':');
        if (colon == std::string_view::npos)
            return bytes;
        std::string name(line.substr(0, colon));
        std::transform(name.begin(), name.end(), name.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        auto value = line.substr(colon + 1);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
            value.remove_prefix(1);
        while (!value.empty() &&
               (value.back() == ' ' || value.back() == '\t' || value.back() == '\r' || value.back() == '\n'))
            value.remove_suffix(1);
        if (name == "content-length") {
            if (t.length || value.empty()) {
                t.invalid = true;
                return 0;
            }
            std::int64_t length = 0;
            for (char c : value) {
                if (c < '0' || c > '9' || length > (max_safe_integer - (c - '0')) / 10) {
                    t.invalid = true;
                    return 0;
                }
                length = length * 10 + c - '0';
            }
            t.length = length;
            if (t.status == 200 && length != t.expected) {
                t.invalid = true;
                return 0;
            }
        } else if (name == "content-encoding") {
            std::string encoding(value);
            std::transform(encoding.begin(), encoding.end(), encoding.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            if (t.encoding_seen || encoding != "identity") {
                t.invalid = true;
                return 0;
            }
            t.encoding_seen = true;
        } else if (name == "location") {
            if (!t.location.empty() || value.size() > 2048) {
                t.invalid = true;
                return 0;
            }
            t.location = std::string(value);
        }
        return bytes;
    } catch (...) {
        t.invalid = true;
        return 0;
    }
}
int progress(void *context, curl_off_t, curl_off_t, curl_off_t, curl_off_t) noexcept {
    return static_cast<Transfer *>(context)->cancelled.load() ? 1 : 0;
}
struct TemporaryFile {
    std::filesystem::path path;
    FILE *file = nullptr;
    explicit TemporaryFile(const std::filesystem::path &destination) {
        path = destination.parent_path() / (".orbit-download-" + new_installation_id());
#ifdef _WIN32
        file = _wfopen(path.c_str(), L"wbx");
#else
        const auto descriptor = ::open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        if (descriptor >= 0) {
            file = fdopen(descriptor, "wb");
            if (!file) {
                ::close(descriptor);
                std::error_code ignored;
                std::filesystem::remove(path, ignored);
            }
        }
#endif
        if (!file)
            raise(ErrorKind::storage, "download_storage_failed");
    }
    ~TemporaryFile() {
        if (file)
            std::fclose(file);
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }
    void finish() {
        if (std::fflush(file) != 0)
            raise(ErrorKind::storage, "download_storage_failed");
#ifdef _WIN32
        if (_commit(_fileno(file)) != 0)
            raise(ErrorKind::storage, "download_storage_failed");
#else
        if (::fsync(fileno(file)) != 0)
            raise(ErrorKind::storage, "download_storage_failed");
#endif
        const auto result = std::fclose(file);
        file = nullptr;
        if (result != 0)
            raise(ErrorKind::storage, "download_storage_failed");
    }
};
struct Easy {
    CURL *value = curl_easy_init();
    ~Easy() {
        if (value)
            curl_easy_cleanup(value);
    }
};
struct Headers {
    curl_slist *value = nullptr;
    ~Headers() { curl_slist_free_all(value); }
    void add(const std::string &line) {
        auto *next = curl_slist_append(value, line.c_str());
        if (!next)
            raise(ErrorKind::internal, "allocation_failed");
        value = next;
    }
};
template <class T> void option(CURL *handle, CURLoption key, T value) {
    if (curl_easy_setopt(handle, key, value) != CURLE_OK)
        raise(ErrorKind::transport_security, "transport_configuration");
}
std::string redirect_url(const std::string &current, const std::string &location) {
    if (location.substr(0, 2) == "//")
        validate_delivery_url("https:" + location, true);
    else if (location.find("://") != std::string::npos)
        validate_delivery_url(location, true);
    if (location.find('#') != std::string::npos)
        raise(ErrorKind::invalid_response, "invalid_redirect");
    std::unique_ptr<CURLU, decltype(&curl_url_cleanup)> url(curl_url(), curl_url_cleanup);
    if (!url || location.empty() || location.find_first_of("\\\r\n\t ") != std::string::npos ||
        curl_url_set(url.get(), CURLUPART_URL, current.c_str(), 0) != CURLUE_OK ||
        curl_url_set(url.get(), CURLUPART_URL, location.c_str(), 0) != CURLUE_OK)
        raise(ErrorKind::invalid_response, "invalid_redirect");
    char *text = nullptr;
    if (curl_url_get(url.get(), CURLUPART_URL, &text, 0) != CURLUE_OK)
        raise(ErrorKind::invalid_response, "invalid_redirect");
    std::unique_ptr<char, decltype(&curl_free)> owned(text, curl_free);
    std::string result(text);
    validate_delivery_url(result, true);
    return result;
}
} // namespace
void download_stream(const DownloadAuthorization &authorization, std::string_view destination,
                     std::int64_t maximum_bytes, bool replace, const std::atomic_bool &cancelled,
                     std::string_view test_ca) {
    validate_authorization(authorization);
    if (destination.empty() || destination.find('\0') != std::string_view::npos || maximum_bytes < 1 ||
        maximum_bytes > max_safe_integer || authorization.artifact.byte_length > maximum_bytes)
        raise(ErrorKind::configuration, "configuration");
    check_cancelled(cancelled.load());
    if (authorization.expires_at && std::chrono::system_clock::now() >= *authorization.expires_at)
        raise(ErrorKind::denied, "download_ticket_expired");
    static std::once_flag initialized;
    static CURLcode initialized_result;
    std::call_once(initialized, [] { initialized_result = curl_global_init(CURL_GLOBAL_DEFAULT); });
    if (initialized_result != CURLE_OK)
        raise(ErrorKind::internal, "transport_initialization_failed");
    try {
#if defined(__cpp_char8_t)
        const auto path = std::filesystem::absolute(std::filesystem::path(
            std::u8string(reinterpret_cast<const char8_t *>(destination.data()), destination.size())));
#else
        const auto path = std::filesystem::absolute(std::filesystem::u8path(destination));
#endif
        if (!replace && std::filesystem::exists(path))
            raise(ErrorKind::storage, "destination_exists");
        TemporaryFile output(path);
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> hash(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!hash || EVP_DigestInit_ex(hash.get(), EVP_sha256(), nullptr) != 1)
            raise(ErrorKind::internal, "hash_failed");
        auto url = authorization.artifact.url;
        for (unsigned redirects = 0;; ++redirects) {
            validate_delivery_url(url, true);
            Easy handle;
            if (!handle.value)
                raise(ErrorKind::internal, "allocation_failed");
            Transfer transfer{output.file, hash.get(), cancelled, authorization.artifact.byte_length,
                              maximum_bytes};
            Headers headers;
            headers.add("Accept-Encoding: identity");
            if (redirects == 0 && authorization.ticket)
                headers.add("Authorization: Bearer " + *authorization.ticket);
            option(handle.value, CURLOPT_URL, url.c_str());
            option(handle.value, CURLOPT_PROTOCOLS_STR, "https");
            option(handle.value, CURLOPT_FOLLOWLOCATION, 0L);
            option(handle.value, CURLOPT_SSL_VERIFYPEER, 1L);
            option(handle.value, CURLOPT_SSL_VERIFYHOST, 2L);
            option(handle.value, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
            option(handle.value, CURLOPT_NETRC, static_cast<long>(CURL_NETRC_IGNORED));
            option(handle.value, CURLOPT_HTTPAUTH, static_cast<long>(CURLAUTH_NONE));
            option(handle.value, CURLOPT_PROXY, "");
            option(handle.value, CURLOPT_HTTP_CONTENT_DECODING, 0L);
            option(handle.value, CURLOPT_HTTPHEADER, headers.value);
            option(handle.value, CURLOPT_NOSIGNAL, 1L);
            option(handle.value, CURLOPT_CONNECTTIMEOUT_MS, 10000L);
            option(handle.value, CURLOPT_TIMEOUT_MS, 30L * 60L * 1000L);
            option(handle.value, CURLOPT_NOPROGRESS, 0L);
            option(handle.value, CURLOPT_XFERINFOFUNCTION, progress);
            option(handle.value, CURLOPT_XFERINFODATA, &transfer);
            option(handle.value, CURLOPT_WRITEFUNCTION, write_bytes);
            option(handle.value, CURLOPT_WRITEDATA, &transfer);
            option(handle.value, CURLOPT_HEADERFUNCTION, read_headers);
            option(handle.value, CURLOPT_HEADERDATA, &transfer);
#ifdef ORBIT_SDK_TESTING
            const std::string ca(test_ca);
            if (!ca.empty())
                option(handle.value, CURLOPT_CAINFO, ca.c_str());
#else
            (void)test_ca;
#endif
            const auto result = curl_easy_perform(handle.value);
            check_cancelled(cancelled.load());
            if (transfer.invalid)
                raise(ErrorKind::invalid_response, "invalid_download");
            if (transfer.io_error)
                raise(ErrorKind::storage, "download_storage_failed");
            if (transfer.status == 301 || transfer.status == 302 || transfer.status == 303 ||
                transfer.status == 307 || transfer.status == 308) {
                if (redirects == 5 || (result != CURLE_OK && result != CURLE_WRITE_ERROR))
                    raise(ErrorKind::invalid_response, "invalid_redirect");
                url = redirect_url(url, transfer.location);
                continue;
            }
            // Seller errors abort the body write; report the status, not a transport failure.
            if (transfer.status != 0 && transfer.status != 200)
                raise(ErrorKind::invalid_response, "download_http_error");
            if (result != CURLE_OK) {
                if (result == CURLE_PARTIAL_FILE)
                    raise(ErrorKind::invalid_response, "truncated_download");
                raise(ErrorKind::transport_security, "download_transport_failed");
            }
            if (transfer.status != 200 || transfer.received != authorization.artifact.byte_length)
                raise(ErrorKind::invalid_response, "invalid_download");
            std::array<unsigned char, 32> digest{};
            unsigned int size = 0;
            if (EVP_DigestFinal_ex(hash.get(), digest.data(), &size) != 1 || size != digest.size())
                raise(ErrorKind::internal, "hash_failed");
            constexpr char hex[] = "0123456789abcdef";
            std::string encoded;
            for (auto byte : digest) {
                encoded += hex[byte >> 4];
                encoded += hex[byte & 15];
            }
            if (encoded != authorization.artifact.sha256)
                raise(ErrorKind::invalid_response, "download_digest_mismatch");
            output.finish();
            check_cancelled(cancelled.load());
            if (!replace)
                std::filesystem::create_hard_link(output.path, path);
            else {
#ifdef _WIN32
                if (!MoveFileExW(output.path.c_str(), path.c_str(),
                                 MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                    raise(ErrorKind::storage, "download_storage_failed");
#else
                std::filesystem::rename(output.path, path);
#endif
            }
            return;
        }
    } catch (const std::filesystem::filesystem_error &) {
        raise(ErrorKind::storage, "download_storage_failed");
    }
}
} // namespace orbit::detail
