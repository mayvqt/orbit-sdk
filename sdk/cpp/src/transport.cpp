#include "transport.hpp"

#include "error.hpp"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#endif

#include <curl/curl.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <climits>
#include <mutex>
#include <thread>

namespace orbit::detail {
namespace {

constexpr std::size_t kMaxBytes = 64 * 1024;
constexpr std::size_t kMaxHeaders = 32 * 1024;
constexpr auto kAttemptTimeout = std::chrono::seconds(10);
constexpr auto kOperationTimeout = std::chrono::seconds(30);
constexpr std::string_view kClientPrefix = "/api/client/v1/";
constexpr std::string_view kJwksPath = "/.well-known/orbit-jwks.json";

bool starts_with(std::string_view value, std::string_view prefix) {
    return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

void ensure_curl() {
    static std::once_flag once;
    static CURLcode result = CURLE_OK;
    static bool asynchronous_dns = false;
    std::call_once(once, [] {
        result = curl_global_init(CURL_GLOBAL_DEFAULT);
        if (result == CURLE_OK) {
            const auto* version = curl_version_info(CURLVERSION_NOW);
            asynchronous_dns = version != nullptr &&
                               (version->features & CURL_VERSION_ASYNCHDNS) != 0;
        }
    });
    if (result != CURLE_OK) raise(ErrorKind::internal, "transport_initialization_failed");
    if (!asynchronous_dns) raise(ErrorKind::configuration, "async_dns_required");
}

struct CurlBuffer {
    std::string body;
    std::size_t header_bytes = 0;
    bool overflow = false;
    bool callback_failed = false;
    std::string retry_after;
};

size_t body_callback(char* data, size_t size, size_t count, void* opaque) {
    auto& buffer = *static_cast<CurlBuffer*>(opaque);
    if (size != 0 && count > static_cast<std::size_t>(-1) / size) {
        buffer.overflow = true;
        return 0;
    }
    const auto bytes = size * count;
    if (bytes > kMaxBytes - buffer.body.size()) {
        buffer.overflow = true;
        return 0;
    }
    try {
        buffer.body.append(data, bytes);
    } catch (...) {
        buffer.callback_failed = true;
        return 0;
    }
    return bytes;
}

size_t header_callback(char* data, size_t size, size_t count, void* opaque) {
    auto& buffer = *static_cast<CurlBuffer*>(opaque);
    if (size != 0 && count > static_cast<std::size_t>(-1) / size) {
        buffer.overflow = true;
        return 0;
    }
    const auto bytes = size * count;
    if (bytes > kMaxHeaders - buffer.header_bytes || bytes > 8192) {
        buffer.overflow = true;
        return 0;
    }
    buffer.header_bytes += bytes;
    std::string_view line(data, bytes);
    const auto colon = line.find(':');
    if (colon != std::string_view::npos) {
        const auto name = line.substr(0, colon);
        constexpr std::string_view retry_after_name = "retry-after";
        const bool is_retry_after = name.size() == retry_after_name.size() &&
            std::equal(name.begin(), name.end(), retry_after_name.begin(),
                       [](unsigned char left, unsigned char right) {
                           return std::tolower(left) == right;
                       });
        if (is_retry_after) {
            auto value = line.substr(colon + 1);
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
            while (!value.empty() && (value.back() == '\r' || value.back() == '\n' || value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
            if (value.size() <= 20) {
                try {
                    buffer.retry_after.assign(value);
                } catch (...) {
                    buffer.callback_failed = true;
                    return 0;
                }
            }
        }
    }
    return bytes;
}

int progress_callback(void* opaque, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
    const auto& cancelled = *static_cast<const std::atomic_bool*>(opaque);
    return cancelled.load(std::memory_order_relaxed) ? 1 : 0;
}

struct EasyHandle {
    CURL* value = curl_easy_init();
    ~EasyHandle() { if (value) curl_easy_cleanup(value); }
};

struct HeaderList {
    curl_slist* value = nullptr;
    ~HeaderList() { curl_slist_free_all(value); }
    void add(const std::string& line) {
        auto* next = curl_slist_append(value, line.c_str());
        if (!next) raise(ErrorKind::internal, "allocation_failed");
        value = next;
    }
};

bool transient_os_error(long value) {
    if (value == 0) return false;
#if defined(_WIN32)
    return value == WSAECONNREFUSED || value == WSAECONNRESET ||
           value == WSAETIMEDOUT || value == WSAEHOSTUNREACH ||
           value == WSAENETUNREACH;
#else
    return value == ECONNREFUSED || value == ECONNRESET || value == ETIMEDOUT ||
           value == EHOSTUNREACH || value == ENETUNREACH;
#endif
}

std::uint32_t retry_after_ms(std::string_view value) {
    if (value.empty() || value.size() > 10) return 0;
    std::uint64_t seconds = 0;
    for (const auto c : value) {
        if (c < '0' || c > '9') return 0;
        seconds = seconds * 10 + static_cast<unsigned>(c - '0');
        if (seconds > 30) return 30000;
    }
    return static_cast<std::uint32_t>(seconds * 1000);
}

bool valid_code(std::string_view value) {
    return !value.empty() && value.size() <= 128 &&
           std::all_of(value.begin(), value.end(), [](unsigned char c) {
               return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
           });
}

bool valid_request_id(std::string_view value) {
    return !value.empty() && value.size() <= 64 &&
           std::all_of(value.begin(), value.end(), [](unsigned char c) {
               return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '_' || c == '-';
           });
}

bool contains_error_member(std::string_view body) {
    return json_has_top_level_member(body, "error");
}

template <class Value>
void set_option(CURL* handle, CURLoption option, Value value) {
    if (curl_easy_setopt(handle, option, value) != CURLE_OK) {
        raise(ErrorKind::internal, "curl_option_failed");
    }
}

std::string get_url_part(CURLU* url, CURLUPart part) {
    char* value = nullptr;
    const auto status = curl_url_get(url, part, &value, 0);
    if (status != CURLUE_OK) return {};
    std::string result(value);
    curl_free(value);
    return result;
}

} // namespace

Transport::Transport(std::string_view origin) {
    ensure_curl();
    if (origin.empty() || origin.size() > 2048 ||
        std::any_of(origin.begin(), origin.end(), [](unsigned char c) { return c <= 0x20 || c == 0x7f; })) {
        raise(ErrorKind::configuration, "configuration");
    }
    const auto separator = origin.find("://");
    if (separator == std::string_view::npos) raise(ErrorKind::configuration, "configuration");
    auto authority = origin.substr(separator + 3);
    if (!authority.empty() && authority.back() == '/') authority.remove_suffix(1);
    if (authority.empty() || authority.find_first_of("/\\@?#") != std::string_view::npos) {
        raise(ErrorKind::configuration, "configuration");
    }
    CURLU* parsed = curl_url();
    if (!parsed) raise(ErrorKind::internal, "allocation_failed");
    const auto cleanup = std::unique_ptr<CURLU, decltype(&curl_url_cleanup)>(parsed, curl_url_cleanup);
    if (curl_url_set(parsed, CURLUPART_URL, std::string(origin).c_str(), 0) != CURLUE_OK ||
        get_url_part(parsed, CURLUPART_SCHEME) != "https" ||
        get_url_part(parsed, CURLUPART_HOST).empty() ||
        !get_url_part(parsed, CURLUPART_USER).empty() ||
        !get_url_part(parsed, CURLUPART_PASSWORD).empty() ||
        !get_url_part(parsed, CURLUPART_QUERY).empty() ||
        !get_url_part(parsed, CURLUPART_FRAGMENT).empty()) {
        raise(ErrorKind::configuration, "configuration");
    }
    auto path = get_url_part(parsed, CURLUPART_PATH);
    if (!path.empty() && path != "/") raise(ErrorKind::configuration, "configuration");
    char* normalized = nullptr;
    if (curl_url_get(parsed, CURLUPART_URL, &normalized, 0) != CURLUE_OK || !normalized) {
        raise(ErrorKind::configuration, "configuration");
    }
    origin_ = normalized;
    curl_free(normalized);
    if (!origin_.empty() && origin_.back() == '/') origin_.pop_back();
}

#ifdef ORBIT_SDK_TESTING
Transport::Transport(std::string origin, TestHandler handler)
    : Transport(origin) {
    test_handler_ = std::move(handler);
}

Transport::Transport(std::string origin, std::string trusted_test_ca_file)
    : Transport(origin) {
    if (trusted_test_ca_file.empty() || trusted_test_ca_file.size() > 4096) {
        raise(ErrorKind::configuration, "configuration");
    }
    trusted_test_ca_file_ = std::move(trusted_test_ca_file);
}
#endif

std::optional<Json::Value> Transport::get(std::string_view path,
                                           const std::atomic_bool& cancelled) const {
    return request("GET", path, {}, {}, true, cancelled);
}

std::optional<Json::Value> Transport::get_bearer(std::string_view path,
                                                  std::string_view bearer,
                                                  const std::atomic_bool& cancelled) const {
    const auto route = path.substr(0, path.find('?'));
    if (route != "/api/client/v1/licences" && route != "/api/client/v1/sessions/current") {
        raise(ErrorKind::configuration, "configuration");
    }
    return request("GET", path, {}, bearer, true, cancelled);
}

std::optional<Json::Value> Transport::delete_bearer(
    std::string_view path, std::string_view bearer,
    const std::atomic_bool& cancelled) const {
    if (path.substr(0, path.find('?')) != "/api/client/v1/sessions/current") {
        raise(ErrorKind::configuration, "configuration");
    }
    return request("DELETE", path, {}, bearer, false, cancelled);
}

std::optional<Json::Value> Transport::post(std::string_view path,
                                           const Json::Value& body,
                                           bool retry_safe,
                                           const std::atomic_bool& cancelled) const {
    const auto encoded = encode_json(body);
    if (encoded.size() > kMaxBytes) raise(ErrorKind::configuration, "request_too_large");
    return request("POST", path, encoded, {}, retry_safe, cancelled);
}

std::string Transport::endpoint(std::string_view path) const {
    const auto query_at = path.find('?');
    const auto route = path.substr(0, query_at);
    const bool has_query = query_at != std::string_view::npos;
    const bool licences = route == "/api/client/v1/licences";
    const bool current_session = route == "/api/client/v1/sessions/current";
    const bool jwks = route == kJwksPath;
    if (path.empty() || route.empty() || path.size() > 2048 ||
        !(starts_with(route, kClientPrefix) || route == kJwksPath) ||
        path.find("//") != std::string_view::npos || path.find('\\') != std::string_view::npos ||
        path.find('#') != std::string_view::npos ||
        route.find('%') != std::string_view::npos || route.back() == '/' ||
        std::any_of(path.begin(), path.end(), [](unsigned char c) { return c <= 0x20 || c == 0x7f; })) {
        raise(ErrorKind::configuration, "configuration");
    }
    for (std::size_t begin = 0; begin < route.size();) {
        const auto end = route.find('/', begin);
        const auto segment = route.substr(begin, end == std::string_view::npos
                                                     ? route.size() - begin
                                                     : end - begin);
        if (segment == "." || segment == "..") {
            raise(ErrorKind::configuration, "configuration");
        }
        if (end == std::string_view::npos) break;
        begin = end + 1;
    }
    if ((!has_query && (licences || current_session)) ||
        (has_query && !(licences || current_session || jwks))) {
        raise(ErrorKind::configuration, "configuration");
    }
    if (has_query) {
        const auto query = path.substr(query_at + 1);
        const auto first = query.find('&');
        const auto second = first == std::string_view::npos ? first : query.find('&', first + 1);
        if (first == std::string_view::npos ||
            (second != std::string_view::npos && !licences) ||
            (second != std::string_view::npos &&
             query.find('&', second + 1) != std::string_view::npos)) {
            raise(ErrorKind::configuration, "configuration");
        }
        const auto part1 = query.substr(0, first);
        const auto part2 = second == std::string_view::npos
                               ? query.substr(first + 1)
                               : query.substr(first + 1, second - first - 1);
        if (!starts_with(part1, "application_id=") || !starts_with(part2, "environment_id=")) {
            raise(ErrorKind::configuration, "configuration");
        }
        auto valid_query_value = [](std::string_view value) {
            return !value.empty() && value.size() <= 128 &&
                   std::all_of(value.begin(), value.end(), [](unsigned char c) {
                       return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                              (c >= '0' && c <= '9') || c == '_' || c == '-';
                   });
        };
        if (!valid_query_value(part1.substr(15)) || !valid_query_value(part2.substr(15))) {
            raise(ErrorKind::configuration, "configuration");
        }
        if (second != std::string_view::npos) {
            const auto part3 = query.substr(second + 1);
            if (!starts_with(part3, "after=") || !valid_query_value(part3.substr(6))) {
                raise(ErrorKind::configuration, "configuration");
            }
        }
        if (route != "/api/client/v1/licences" && route != "/api/client/v1/sessions/current" && route != kJwksPath) {
            raise(ErrorKind::configuration, "configuration");
        }
    }
    return origin_ + std::string(path);
}

HttpResponse Transport::attempt(std::string_view method, std::string_view url,
                                std::string_view body, std::string_view bearer,
                                const std::atomic_bool& cancelled, long timeout_ms) const {
#ifdef ORBIT_SDK_TESTING
    if (test_handler_) return test_handler_(method, url, bearer, body, cancelled);
#endif
    check_cancelled(cancelled.load(std::memory_order_relaxed));
    EasyHandle handle;
    if (!handle.value) raise(ErrorKind::internal, "allocation_failed");
    CurlBuffer buffer;
    char error[CURL_ERROR_SIZE] = {};
    const std::string owned_url(url);
    set_option(handle.value, CURLOPT_URL, owned_url.c_str());
    set_option(handle.value, CURLOPT_PROTOCOLS_STR, "https");
    set_option(handle.value, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    set_option(handle.value, CURLOPT_FOLLOWLOCATION, 0L);
    set_option(handle.value, CURLOPT_MAXREDIRS, 0L);
    set_option(handle.value, CURLOPT_SSL_VERIFYPEER, 1L);
    set_option(handle.value, CURLOPT_SSL_VERIFYHOST, 2L);
    set_option(handle.value, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
#ifdef ORBIT_SDK_TESTING
    if (!trusted_test_ca_file_.empty()) {
        set_option(handle.value, CURLOPT_CAINFO, trusted_test_ca_file_.c_str());
    }
#endif
    set_option(handle.value, CURLOPT_NOSIGNAL, 1L);
    set_option(handle.value, CURLOPT_CONNECTTIMEOUT_MS, std::min(5000L, timeout_ms));
    set_option(handle.value, CURLOPT_TIMEOUT_MS, timeout_ms);
    set_option(handle.value, CURLOPT_ERRORBUFFER, error);
    set_option(handle.value, CURLOPT_WRITEFUNCTION, body_callback);
    set_option(handle.value, CURLOPT_WRITEDATA, &buffer);
    set_option(handle.value, CURLOPT_HEADERFUNCTION, header_callback);
    set_option(handle.value, CURLOPT_HEADERDATA, &buffer);
    set_option(handle.value, CURLOPT_XFERINFOFUNCTION, progress_callback);
    set_option(handle.value, CURLOPT_XFERINFODATA, &cancelled);
    set_option(handle.value, CURLOPT_NOPROGRESS, 0L);
    set_option(handle.value, CURLOPT_USERAGENT, "Orbit-Cpp-SDK/0.2.0");
    HeaderList headers;
    headers.add("Accept: application/json");
    if (!bearer.empty()) {
        if (bearer.size() > 256 || !std::all_of(bearer.begin(), bearer.end(), [](unsigned char c) {
                return std::isalnum(c) || c == '_' || c == '-';
            })) raise(ErrorKind::configuration, "configuration");
        headers.add("Authorization: Bearer " + std::string(bearer));
    }
    if (method == "POST") {
        headers.add("Content-Type: application/json");
        set_option(handle.value, CURLOPT_POST, 1L);
        set_option(handle.value, CURLOPT_POSTFIELDS, body.data());
        set_option(handle.value, CURLOPT_POSTFIELDSIZE_LARGE,
                   static_cast<curl_off_t>(body.size()));
    } else if (method == "DELETE") {
        set_option(handle.value, CURLOPT_CUSTOMREQUEST, "DELETE");
    }
    set_option(handle.value, CURLOPT_HTTPHEADER, headers.value);
    const auto result = curl_easy_perform(handle.value);
    if (cancelled.load(std::memory_order_relaxed)) raise(ErrorKind::cancelled, "cancelled");
    if (buffer.callback_failed) raise(ErrorKind::internal, "allocation_failed");
    if (buffer.overflow) raise(ErrorKind::invalid_response, "invalid_response");
    if (result != CURLE_OK) {
        long os_error = 0;
        (void)curl_easy_getinfo(handle.value, CURLINFO_OS_ERRNO, &os_error);
        if (result == CURLE_OPERATION_TIMEDOUT || transient_os_error(os_error)) {
            raise(ErrorKind::transient, "service_unavailable");
        }
        if (result == CURLE_GOT_NOTHING || result == CURLE_PARTIAL_FILE) {
            raise(ErrorKind::invalid_response, "invalid_response");
        }
        raise(ErrorKind::transport_security, "transport_security");
    }
    HttpResponse response;
    if (curl_easy_getinfo(handle.value, CURLINFO_RESPONSE_CODE, &response.status) != CURLE_OK) {
        raise(ErrorKind::internal, "curl_response_info_failed");
    }
    response.body = std::move(buffer.body);
    response.retry_after = std::move(buffer.retry_after);
    return response;
}

std::optional<Json::Value> Transport::request(
    std::string_view method, std::string_view path, std::string_view body,
    std::string_view bearer, bool retry_safe,
    const std::atomic_bool& cancelled) const {
    check_cancelled(cancelled.load(std::memory_order_relaxed));
    const auto url = endpoint(path);
    const auto deadline = std::chrono::steady_clock::now() + kOperationTimeout;
    auto sleep_before_retry = [&](unsigned attempt_number, std::string_view retry_after) {
        std::uint8_t entropy = 0;
        if (RAND_bytes(&entropy, sizeof(entropy)) != 1) raise(ErrorKind::transport_security, "transport_security");
        const auto backoff = std::chrono::milliseconds((250u + entropy) << attempt_number);
        const auto server_delay = std::chrono::milliseconds(retry_after_ms(retry_after));
        const auto delay = std::max(backoff, server_delay);
        auto until = std::chrono::steady_clock::now() + delay;
        if (until >= deadline) return false;
        while (until > std::chrono::steady_clock::now()) {
            check_cancelled(cancelled.load(std::memory_order_relaxed));
            std::this_thread::sleep_for(std::min(std::chrono::milliseconds(25),
                std::chrono::duration_cast<std::chrono::milliseconds>(until - std::chrono::steady_clock::now())));
        }
        return true;
    };
    for (unsigned attempt_number = 0; attempt_number <= 2; ++attempt_number) {
        HttpResponse response;
        try {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
            if (remaining <= std::chrono::milliseconds::zero()) raise(ErrorKind::transient, "service_unavailable");
            const auto timeout = std::min(
                std::chrono::duration_cast<std::chrono::milliseconds>(kAttemptTimeout), remaining);
            response = attempt(method, url, body, bearer, cancelled, static_cast<long>(timeout.count()));
        } catch (const Error& error) {
            if (error.kind() != ErrorKind::transient || !retry_safe || attempt_number == 2) throw;
            if (!sleep_before_retry(attempt_number, {})) throw;
            continue;
        }
        check_cancelled(cancelled.load(std::memory_order_relaxed));
        const auto status = response.status;
        if (status == 204) {
            if (!response.body.empty()) raise(ErrorKind::invalid_response, "invalid_response");
            return std::nullopt;
        }
        if (status >= 200 && status < 300) return parse_json(response.body);
        const bool is_error = contains_error_member(response.body);
        if (status >= 502 && status <= 504 && !is_error) {
            if (!retry_safe || attempt_number == 2) raise(ErrorKind::transient, "service_unavailable");
            if (!sleep_before_retry(attempt_number, response.retry_after)) raise(ErrorKind::transient, "service_unavailable");
            continue;
        }
        if (!(status == 401 || status == 403 || status == 404 || status == 409 ||
              status == 422 || status == 429 || (status >= 500 && status <= 599))) {
            raise(ErrorKind::invalid_response, "invalid_response");
        }
        const auto envelope = parse_json(response.body);
        if (!envelope.isObject() || !envelope.isMember("error") || !envelope["error"].isObject()) {
            raise(ErrorKind::invalid_response, "invalid_response");
        }
        const auto& error = envelope["error"];
        if (!error["code"].isString() || !error["message"].isString() ||
            !error["request_id"].isString()) raise(ErrorKind::invalid_response, "invalid_response");
        const auto code = error["code"].asString();
        const auto message = error["message"].asString();
        const auto request_id = error["request_id"].asString();
        if (!valid_code(code) || message.empty() || !valid_request_id(request_id)) {
            raise(ErrorKind::invalid_response, "invalid_response");
        }
        const bool temporary = (status == 429 && code == "rate_limited") ||
                               (status == 503 && code == "service_unavailable");
        if (temporary && retry_safe && attempt_number < 2) {
            if (!sleep_before_retry(attempt_number, response.retry_after)) {
                raise(ErrorKind::transient, code, request_id);
            }
            continue;
        }
        raise(temporary ? ErrorKind::transient : ErrorKind::denied, code, request_id);
    }
    raise(ErrorKind::transient, "service_unavailable");
}

} // namespace orbit::detail
