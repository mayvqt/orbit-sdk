#include "core.hpp"

#include "error.hpp"
#include "storage_windows.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>
#if defined(__linux__)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace {

using namespace orbit;
using namespace orbit::detail;

std::string timestamp_for_test(std::int64_t seconds) {
    const auto value = static_cast<std::time_t>(seconds);
    std::tm broken_down{};
#if defined(_WIN32)
    gmtime_s(&broken_down, &value);
#else
    gmtime_r(&value, &broken_down);
#endif
    char buffer[32]{};
    if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &broken_down) == 0)
        throw std::runtime_error("test timestamp formatting failed");
    return buffer;
}

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

template <class F>
Error expect_error(F&& function, ErrorKind kind) {
    try {
        function();
    } catch (const Error& error) {
        require(error.kind() == kind, "unexpected Orbit error kind");
        return error;
    }
    throw std::runtime_error("expected Orbit error");
}

struct Corpus {
    Json::Value value;
    Json::Value jwks;
    Json::Value expected;
};

Corpus load_corpus() {
    std::ifstream input(ORBIT_GRANT_VECTORS_PATH, std::ios::binary);
    require(input.good(), "could not open shared grant corpus");
    std::string bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    auto value = parse_json(bytes, 2 * 1024 * 1024);
    require(value["format_version"].asInt() == 1, "unexpected grant corpus version");
    require(value["cases"].isArray() && value["cases"].size() == 104, "shared corpus must contain all 104 vectors");
    return {value, value["jwks"], value["expected"]};
}

Json::Value load_app_key_corpus() {
    std::ifstream input(ORBIT_APP_KEY_VECTORS_PATH, std::ios::binary);
    require(input.good(), "could not open shared app-key corpus");
    std::string bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    auto value = parse_json(bytes, 256 * 1024);
    require(value["format_version"].asInt() == 1 && value["cases"].isArray(),
            "unexpected app-key corpus format");
    return value;
}

std::string text(const Json::Value& value, const char* name) {
    require(value[name].isString(), std::string("missing string field ") + name);
    return value[name].asString();
}

std::size_t test_shared_app_key_vectors() {
    const auto corpus = load_app_key_corpus();
    std::size_t valid = 0;
    std::size_t invalid = 0;
    for (const auto& item : corpus["cases"]) {
        bool accepted = false;
        try {
            const auto parsed = AppKey::parse(text(item, "key"));
            accepted = true;
            require(parsed.api_origin() == text(item, "api_origin") &&
                        parsed.issuer() == text(item, "issuer") &&
                        parsed.application_id() == text(item, "application_id") &&
                        parsed.environment_id() == text(item, "environment_id") &&
                        parsed.environment() == text(item, "environment"),
                    "app-key vector output mismatch: " + text(item, "name"));
        } catch (const Error& error) {
            require(error.kind() == ErrorKind::configuration,
                    "app-key vector failed with a non-configuration error");
        }
        const bool expected = item["valid"].asBool();
        require(accepted == expected, "app-key vector mismatch: " + text(item, "name"));
        expected ? ++valid : ++invalid;
    }
    require(valid > 0 && invalid > 0, "app-key corpus must exercise valid and invalid cases");
    return corpus["cases"].size();
}

void test_fingerprint_options() {
    const auto key = AppKey::parse(
        "orbit_app_test_aHR0cHM6Ly9vcmJpdC5tYXl2aWUuZGV2.Q2lK7xY3bR9mT0pW4vN8sA.Zx8_c-1dKpL5qR2tU6wY0g");
    const auto automatic = resolve_fingerprint(key, Options{});
    if (automatic) {
        require(automatic->provider == "machine_v1" && automatic->value.size() == 64 &&
                    std::all_of(automatic->value.begin(), automatic->value.end(), [](char c) {
                        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                    }),
                "automatic fingerprint must use the scoped machine_v1 digest");
    }
    Options disabled;
    disabled.disable_machine_binding = true;
    require(!resolve_fingerprint(key, disabled), "disabled machine binding must omit fingerprint");
    Options custom;
    custom.fingerprint = Fingerprint{std::string(64, 'a'), "custom:fixture"};
    const auto supplied = resolve_fingerprint(key, custom);
    require(supplied && supplied->value == custom.fingerprint->value &&
                supplied->provider == custom.fingerprint->provider,
            "custom fingerprint option must be preserved");
    custom.disable_machine_binding = true;
    expect_error([&] { (void)resolve_fingerprint(key, custom); }, ErrorKind::configuration);
}

std::string base64url_encode(const unsigned char* bytes, std::size_t size) {
    std::string encoded(4 * ((size + 2) / 3), '\0');
    const auto length = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(encoded.data()), bytes,
                                        static_cast<int>(size));
    require(length >= 0, "test base64 encoding failed");
    encoded.resize(static_cast<std::size_t>(length));
    while (!encoded.empty() && encoded.back() == '=') encoded.pop_back();
    for (auto& c : encoded) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    return encoded;
}

std::string base64url_decode(std::string_view input) {
    std::string padded(input);
    for (auto& c : padded) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    const auto padding = (4 - padded.size() % 4) % 4;
    padded.append(padding, '=');
    std::string decoded(3 * (padded.size() / 4), '\0');
    const auto length = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(decoded.data()),
                                        reinterpret_cast<const unsigned char*>(padded.data()),
                                        static_cast<int>(padded.size()));
    require(length >= 0 && static_cast<std::size_t>(length) >= padding,
            "test base64 decoding failed");
    decoded.resize(static_cast<std::size_t>(length) - padding);
    return decoded;
}

std::string sign_test_token(const Json::Value& claims,
                            std::string_view purpose = "orbit-access+jwt",
                            std::string_view key_id = "test-key") {
    Json::Value header(Json::objectValue);
    header["alg"] = "ES256";
    header["typ"] = std::string(purpose);
    header["kid"] = std::string(key_id);
    const auto header_json = encode_json(header);
    const auto claims_json = encode_json(claims);
    const auto signing_input = base64url_encode(
        reinterpret_cast<const unsigned char*>(header_json.data()), header_json.size()) + "." +
        base64url_encode(reinterpret_cast<const unsigned char*>(claims_json.data()), claims_json.size());
    std::ifstream key_file(ORBIT_GRANT_PRIVATE_KEY_PATH, std::ios::binary);
    require(key_file.good(), "test grant signing key is unavailable");
    std::string key_bytes((std::istreambuf_iterator<char>(key_file)),
                          std::istreambuf_iterator<char>());
    require(!key_bytes.empty() &&
                key_bytes.size() <= static_cast<std::size_t>(std::numeric_limits<int>::max()),
            "test grant signing key has an invalid size");
    BIO* bio = BIO_new_mem_buf(key_bytes.data(), static_cast<int>(key_bytes.size()));
    require(bio != nullptr, "test grant signing BIO allocation failed");
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    require(key != nullptr, "test grant signing key could not be read");
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    require(context != nullptr, "test grant signing context allocation failed");
    std::size_t der_size = 0;
    const auto initialized = EVP_DigestSignInit(context, nullptr, EVP_sha256(), nullptr, key) == 1;
    const auto sized = initialized && EVP_DigestSign(context, nullptr, &der_size,
        reinterpret_cast<const unsigned char*>(signing_input.data()), signing_input.size()) == 1;
    std::string der(der_size, '\0');
    const auto signed_ok = sized && EVP_DigestSign(context, reinterpret_cast<unsigned char*>(der.data()),
        &der_size, reinterpret_cast<const unsigned char*>(signing_input.data()), signing_input.size()) == 1;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    require(signed_ok, "test grant signing failed");
    der.resize(der_size);
    const unsigned char* cursor = reinterpret_cast<const unsigned char*>(der.data());
    ECDSA_SIG* signature = d2i_ECDSA_SIG(nullptr, &cursor, static_cast<long>(der.size()));
    require(signature != nullptr, "test grant signature encoding failed");
    const BIGNUM *r = nullptr, *s = nullptr;
    ECDSA_SIG_get0(signature, &r, &s);
    std::array<unsigned char, 64> raw{};
    const auto converted = BN_bn2binpad(r, raw.data(), 32) == 32 &&
                           BN_bn2binpad(s, raw.data() + 32, 32) == 32;
    ECDSA_SIG_free(signature);
    require(converted, "test grant signature conversion failed");
    return signing_input + "." + base64url_encode(raw.data(), raw.size());
}

std::string token_for_installation(std::string_view token, std::string_view installation) {
    const auto first = token.find('.');
    const auto second = token.find('.', first + 1);
    require(first != std::string_view::npos && second != std::string_view::npos,
            "test grant token is malformed");
    auto claims = parse_json(base64url_decode(token.substr(first + 1, second - first - 1)));
    claims["installation_id"] = std::string(installation);
    return sign_test_token(claims);
}

std::string token_with_claim(std::string_view token, std::string_view name,
                             const Json::Value& value) {
    const auto first = token.find('.');
    const auto second = token.find('.', first + 1);
    require(first != std::string_view::npos && second != std::string_view::npos,
            "test grant token is malformed");
    auto claims = parse_json(base64url_decode(token.substr(first + 1, second - first - 1)));
    claims[std::string(name)] = value;
    return sign_test_token(claims);
}

std::optional<std::string_view> optional_view(const Json::Value& value, const char* name,
                                              std::string& storage) {
    if (!value.isMember(name) || value[name].isNull()) return std::nullopt;
    storage = value[name].asString();
    return storage;
}

GrantExpected vector_expected(const Json::Value& value) {
    static thread_local std::string issuer;
    static thread_local std::string application;
    static thread_local std::string environment;
    static thread_local std::string activation;
    static thread_local std::string installation;
    static thread_local std::string licence;
    static thread_local std::string fingerprint;
    static thread_local std::string provider;
    issuer = text(value, "issuer");
    application = text(value, "application");
    environment = text(value, "environment");
    activation = text(value, "activation");
    installation = text(value, "installation");
    licence.clear(); fingerprint.clear(); provider.clear();
    const auto lic = optional_view(value, "licence", licence);
    const auto fp = optional_view(value, "fingerprint", fingerprint);
    const auto prov = optional_view(value, "fingerprint_provider", provider);
    return GrantExpected{
        issuer, application, environment,
        lic, activation, installation, fp, prov,
        value["credential_expires_at"].isNull() ? std::nullopt : std::optional<std::int64_t>(value["credential_expires_at"].asInt64()),
        value["licence_expires_at"].isNull() ? std::nullopt : std::optional<std::int64_t>(value["licence_expires_at"].asInt64()),
        value["now"].asInt64(), false, std::nullopt,
    };
}

void test_shared_grant_vectors(const Corpus& corpus) {
    std::size_t valid = 0;
    std::size_t invalid = 0;
    for (const auto& item : corpus.value["cases"]) {
        auto expected_value = corpus.expected;
        if (item.isMember("expected")) {
            for (const auto& key : item["expected"].getMemberNames()) expected_value[key] = item["expected"][key];
        }
        const auto jwks = item.isMember("jwks") ? item["jwks"] : corpus.jwks;
        bool accepted = false;
        try {
            const auto keys = GrantKeys::parse(jwks);
            (void)keys.verify(text(item, "token"), vector_expected(expected_value));
            accepted = true;
        } catch (const Error& error) {
            require(error.kind() == ErrorKind::invalid_response, "grant vector failed with non-validation error");
        }
        const bool expected_valid = item["valid"].asBool();
        require(accepted == expected_valid, "grant vector mismatch: " + text(item, "name"));
        expected_valid ? ++valid : ++invalid;
    }
    require(valid == 12 && invalid == 92, "grant corpus valid/invalid case counts changed");

    std::string strict_token;
    for (const auto& item : corpus.value["cases"]) {
        if (item["name"] == "strict-valid") strict_token = text(item, "token");
    }
    require(!strict_token.empty(), "strict-valid grant vector is missing");
    const auto wide_policy = token_with_claim(strict_token, "policy_version", Json::Int64{2147483648LL});
    const auto keys = GrantKeys::parse(corpus.jwks);
    const auto expected = vector_expected(corpus.expected);
    expect_error([&] { (void)keys.verify(wide_policy, expected); }, ErrorKind::invalid_response);

    const std::string runtime_fingerprint(64, 'a');
    const std::string runtime_provider = "machine_v1";
    auto optional_binding = expected;
    optional_binding.fingerprint = runtime_fingerprint;
    optional_binding.fingerprint_provider = runtime_provider;
    optional_binding.allow_unbound_fingerprint = true;
    optional_binding.expected_binding_mode = "none";
    require(keys.verify(strict_token, optional_binding).binding_mode == "none",
            "runtime verification must accept a signed unbound grant with an optional device identity");
    auto strict_binding = optional_binding;
    strict_binding.allow_unbound_fingerprint = false;
    expect_error([&] { (void)keys.verify(strict_token, strict_binding); }, ErrorKind::invalid_response);
    auto provider_only_context = expected;
    provider_only_context.fingerprint.reset();
    provider_only_context.fingerprint_provider = runtime_provider;
    expect_error([&] { (void)keys.verify(strict_token, provider_only_context); },
                 ErrorKind::invalid_response);
    auto wrong_mode = optional_binding;
    wrong_mode.expected_binding_mode = "hwid";
    expect_error([&] { (void)keys.verify(strict_token, wrong_mode); }, ErrorKind::invalid_response);
}

std::size_t test_shared_session_vectors() {
    std::ifstream input(ORBIT_SESSION_VECTORS_PATH, std::ios::binary);
    require(input.good(), "shared session vector file is unavailable");
    const auto corpus =
        parse_json(std::string((std::istreambuf_iterator<char>(input)), {}), 4 * 1024 * 1024);
    require(corpus["format_version"].asInt() == 1 && corpus["cases"].isArray() &&
                corpus["cases"].size() == 184,
            "shared session corpus must contain all 184 vectors");
    const auto &context = corpus["expected"];
    auto base = vector_expected(context);
    const auto session_id = text(context, "session_id");
    const auto sequence = context["sequence"].asInt64();
    std::size_t passed = 0;
    for (const auto &item : corpus["cases"]) {
        auto expected_context = context;
        if (item.isMember("expected"))
            for (const auto &name : item["expected"].getMemberNames())
                expected_context[name] = item["expected"][name];
        const auto jwks = item.isMember("jwks") ? item["jwks"] : corpus["jwks"];
        auto grant = vector_expected(expected_context);
        grant.allow_unbound_fingerprint = expected_context["allow_unbound_fingerprint"].asBool();
        const auto expected_session =
            item.isMember("expected") && item["expected"].isMember("session_id")
                ? text(item["expected"], "session_id")
                : session_id;
        const auto expected_sequence =
            item.isMember("expected") && item["expected"].isMember("sequence")
                ? item["expected"]["sequence"].asInt64()
                : sequence;
        bool accepted = false;
        try {
            const auto keys =
                orbit::detail::SessionKeys::parse(jwks, text(expected_context, "key_environment"));
            (void)keys.verify(text(item, "token"),
                              SessionExpected{grant, expected_session, expected_sequence});
            accepted = true;
        } catch (const Error &error) {
            require(error.kind() == ErrorKind::invalid_response ||
                        error.kind() == ErrorKind::configuration,
                    "session vector failed with non-validation error");
        }
        require(accepted == item["valid"].asBool(),
                "session vector mismatch: " + text(item, "name"));
        ++passed;
    }
    require(!base.issuer.empty(), "session vectors omitted the trusted issuer");
    return passed;
}

void test_strict_bounded_json() {
    for (const std::string bad : {
             "{\"a\":1,\"a\":2}", "/*comment*/{}", "{\"a\":1,}", "{} {}", "{\"a\":NaN}",
             "[1,,2]", "{\"a\":'x'}", "[\"\\ud800\"]"}) {
        expect_error([&] { (void)parse_json(bad); }, ErrorKind::invalid_response);
    }
    std::string invalid_utf8{"{\"x\":\"", 6};
    invalid_utf8.push_back(static_cast<char>(0xc0));
    invalid_utf8 += "\"}";
    expect_error([&] { (void)parse_json(invalid_utf8); }, ErrorKind::invalid_response);
    expect_error([&] { (void)parse_json("{}", 1); }, ErrorKind::invalid_response);
    for (const auto floating : {"1.0", "1e0"}) {
        expect_error([&] { (void)json_int64(parse_json(std::string("{\"v\":") + floating + "}")["v"]); },
                     ErrorKind::invalid_response);
    }
    require(parse_json("{\"value\":true}")["value"].asBool(), "strict parser rejected valid JSON");
    const std::string deep = std::string(200, '[') + std::string(200, ']');
    expect_error([&] { (void)parse_json(deep); }, ErrorKind::invalid_response);
    const auto array = parse_json("[1]");
    expect_error([&] { (void)GrantKeys::parse(array); }, ErrorKind::invalid_response);
}

std::string read_test_file(const char* path) {
    std::ifstream input(path, std::ios::binary);
    require(input.good(), "could not open test file");
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void test_public_key_set_parsing() {
    const auto offline_jwks = encode_json(parse_json(read_test_file(ORBIT_OFFLINE_VECTORS_PATH), 2 * 1024 * 1024)["jwks"]);
    const auto session_jwks = encode_json(parse_json(read_test_file(ORBIT_SESSION_VECTORS_PATH), 4 * 1024 * 1024)["jwks"]);
    require(orbit::OfflineKeys::parse(offline_jwks).environment() == "test",
            "offline key environment was not inferred");
    require(orbit::OfflineKeys::parse(offline_jwks, "test").environment() == "test",
            "explicit offline key environment was not kept");
    require(orbit::SessionKeys::parse(session_jwks).environment() == "test",
            "session key environment was not inferred");
    for (const auto* bad : {"{}", "{\"keys\":[]}", "[1]", "not json"}) {
        const auto error = expect_error([&] { (void)orbit::OfflineKeys::parse(bad); },
                                        ErrorKind::configuration);
        require(error.code() == "invalid_offline_keys", "unexpected offline key error code");
    }
    const auto live = expect_error([&] { (void)orbit::OfflineKeys::parse(offline_jwks, "live"); },
                                   ErrorKind::configuration);
    require(live.code() == "invalid_offline_keys", "unexpected offline key environment error");
    expect_error([&] { (void)orbit::OfflineKeys::parse(session_jwks); }, ErrorKind::configuration);
    const auto session = expect_error([&] { (void)orbit::SessionKeys::parse(offline_jwks); },
                                      ErrorKind::configuration);
    require(session.code() == "invalid_session_keys", "unexpected session key error code");
    require(std::string(Error(1, ErrorKind::denied, "licence_revoked", {}).what()) ==
                "Orbit SDK operation failed: licence_revoked",
            "error text omitted its code");
}

struct Gate {
    std::mutex mutex;
    std::condition_variable condition;
    bool entered = false;
    bool released = false;
    void block() {
        std::unique_lock<std::mutex> lock(mutex);
        entered = true;
        condition.notify_all();
        condition.wait(lock, [&] { return released; });
    }
    void wait_until_entered() {
        std::unique_lock<std::mutex> lock(mutex);
        condition.wait(lock, [&] { return entered; });
    }
    void release() {
        std::lock_guard<std::mutex> lock(mutex);
        released = true;
        condition.notify_all();
    }
};

struct TestStorage final : CredentialStorage {
    std::mutex mutex;
    std::uint64_t generation = 0;
    std::size_t version_reads = 0;
    std::optional<Json::Value> credential;

    std::uint64_t version() override {
        std::lock_guard<std::mutex> lock(mutex);
        ++version_reads;
        return generation;
    }
    std::pair<std::uint64_t, std::optional<Json::Value>> load() override {
        std::lock_guard<std::mutex> lock(mutex);
        return {generation, credential};
    }
    void save(std::uint64_t expected, const Json::Value& value) override {
        std::lock_guard<std::mutex> lock(mutex);
        if (expected != generation) throw Error(1, ErrorKind::stale_response, "stale_response", {});
        credential = value;
    }
    std::uint64_t invalidate() override {
        std::lock_guard<std::mutex> lock(mutex);
        ++generation;
        credential.reset();
        return generation;
    }
};

Json::Value activation_reply(const Json::Value& corpus, bool offline = false,
                             std::string_view installation = "installation_123456",
                             bool persistent = false, bool include_credential = true) {
    const auto wanted = offline ? "desktop-valid" : "strict-valid";
    for (const auto& item : corpus["cases"]) {
        if (item["name"] == wanted) {
            Json::Value reply(Json::objectValue);
            reply["activation_id"] = "activation";
            reply["installation_id"] = std::string(installation);
            if (include_credential) reply["credential"] = std::string(43, 'c');
            reply["credential_expires_at"] = persistent
                ? Json::Value(Json::nullValue) : Json::Value("2027-01-16T09:00:00Z");
            auto grant = token_for_installation(text(item, "token"), installation);
            if (persistent && offline) {
                grant = token_with_claim(grant, "refresh_after", Json::Int64{1800000900});
            }
            reply["grant"] = std::move(grant);
            reply["server_time"] = "2027-01-15T08:00:00Z";
            reply["binding_mode"] = "none";
            reply["fingerprint_provider"] = Json::nullValue;
            reply["licence_expires_at"] = Json::nullValue;
            reply["secret_replay_expired"] = false;
            return reply;
        }
    }
    throw std::runtime_error("grant vector missing activation token");
}

Config config() {
    Config value;
    value.api_origin = "https://example.test";
    value.application_id = "app";
    value.environment_id = "test";
    value.environment = "test";
    value.issuer = "https://orbit.example.test";
    value.installation_id = "installation_123456";
    return value;
}

struct ApiFixture {
    Json::Value corpus;
    std::shared_ptr<TestStorage> storage = std::make_shared<TestStorage>();
    std::mutex mutex;
    std::vector<std::string> requests;
    std::atomic_int activation_calls{0};
    std::atomic_int jwks_calls{0};
    std::atomic_int validate_calls{0};
    std::atomic_int forced_jwks_failures{0};
    std::atomic_bool offline_refresh{false};
    std::atomic_bool tls_failure_refresh{false};
    std::atomic_bool offline_activation{false};
    std::atomic_bool persistent_mode{false};
    std::atomic_bool malformed_activation{false};
    std::atomic_bool finite_persistent_response{false};
    std::atomic_bool missing_expiry{false};
    std::atomic_bool pre_epoch_server_time{false};
    std::atomic_bool far_future_metadata{false};
    std::atomic<std::int64_t> offline_file_seconds{86400};
    std::atomic_bool omit_offline_file_seconds{false};
    std::atomic_int omit_limit_map{0};
    std::atomic_bool activation_response_lost{false};
    std::atomic_bool floating_session{false};
    std::atomic_bool fail_first_session_start{false};
    std::atomic_bool fail_first_session_renewal{false};
    std::atomic_int session_renew_failures{0};
    std::atomic_bool deny_session_renewal{false};
    std::atomic_bool deny_session_start{false};
    std::atomic_int session_start_calls{0};
    std::atomic_int session_renew_calls{0};
    std::atomic_int session_end_calls{0};
    std::vector<std::string> session_ids;
    std::vector<std::int64_t> session_sequences;
    std::function<void()> before_session_start;
    std::atomic_bool login_denied{false};
    std::string last_activation_idempotency;
    std::string last_previous_credential;
    std::shared_ptr<Gate> activation_gate;
    std::shared_ptr<Gate> jwks_gate;
    std::shared_ptr<Gate> sessions_gate;
    std::shared_ptr<Gate> session_gate;
    std::shared_ptr<Gate> logout_gate;
    std::shared_ptr<Gate> deactivation_gate;
    std::shared_ptr<Gate> registration_gate;
    std::shared_ptr<Gate> resend_gate;
    std::shared_ptr<Gate> recovery_gate;
    std::atomic_bool logout_error{false};
    std::atomic_bool deactivation_error{false};

    explicit ApiFixture(Json::Value vectors) : corpus(std::move(vectors)) {}

    Transport::TestHandler handler() {
        return [this](std::string_view method, std::string_view url, std::string_view bearer_value,
                      std::string_view body, const CancellationView& cancelled) {
            (void)cancelled;
            {
                std::lock_guard<std::mutex> lock(mutex);
                requests.emplace_back(std::string(method) + " " + std::string(url));
            }
            const auto route = url.substr(std::string_view("https://example.test").size());
            if (route.find("/.well-known/orbit-jwks.json") == 0) {
                ++jwks_calls;
                if (jwks_gate)
                    jwks_gate->block();
                auto failing = forced_jwks_failures.load();
                while (failing > 0 && !forced_jwks_failures.compare_exchange_weak(failing, failing - 1)) {}
                if (failing > 0) return HttpResponse{503, "{}", "0"};
                return HttpResponse{200, encode_json(corpus["jwks"]), {}};
            }
            if (route.find("/api/client/v1/activations/") == 0 &&
                route.find("/deactivate") != std::string_view::npos) {
                if (deactivation_gate) deactivation_gate->block();
                if (deactivation_error.load()) {
                    return HttpResponse{403,
                        R"({"error":{"code":"activation_revoked","message":"Revoked","request_id":"deactivate_1"}})", {}};
                }
                return HttpResponse{204, {}, {}};
            }
            if (route.find("/api/client/v1/activations/activation/sessions") == 0) {
                const auto input = parse_json(body);
                if (route.find("/end") != std::string_view::npos) {
                    ++session_end_calls;
                    return HttpResponse{204, {}, {}};
                }
                constexpr std::string_view start_suffix = "/sessions";
                const bool start = route.size() >= start_suffix.size() &&
                                   route.substr(route.size() - start_suffix.size()) == start_suffix;
                const auto id = start ? input["session_id"].asString() : [&] {
                    const auto start_pos = route.find("/sessions/") + 10;
                    const auto slash = route.find('/', start_pos);
                    return std::string(route.substr(start_pos, slash - start_pos));
                }();
                const auto sequence = start ? std::int64_t{1} : input["sequence"].asInt64();
                if (start) {
                    if (before_session_start)
                        before_session_start();
                    ++session_start_calls;
                    std::lock_guard<std::mutex> lock(mutex);
                    session_ids.push_back(id);
                } else {
                    ++session_renew_calls;
                    std::lock_guard<std::mutex> lock(mutex);
                    session_sequences.push_back(sequence);
                }
                if (session_gate)
                    session_gate->block();
                if (start && deny_session_start.load())
                    return HttpResponse{
                        409,
                        R"({"error":{"code":"session_sequence_conflict","message":"Stale session ID","request_id":"session_conflict_1"}})",
                        {}};
                if (start && fail_first_session_start.exchange(false))
                    return HttpResponse{503, "{}", {}};
                if (!start && fail_first_session_renewal.exchange(false))
                    return HttpResponse{503, "{}", {}};
                if (!start && deny_session_renewal.load())
                    return HttpResponse{
                        403,
                        R"({"error":{"code":"session_ended","message":"Ended","request_id":"session_end_1"}})",
                        {}};
                if (!start) {
                    auto failures = session_renew_failures.load();
                    while (failures > 0 &&
                           !session_renew_failures.compare_exchange_weak(failures, failures - 1)) {
                    }
                    if (failures > 0)
                        return HttpResponse{503, "{}", {}};
                }
                const auto now = capture_clock().wall_seconds;
                Json::Value claims(Json::objectValue);
                claims["iss"] = "https://orbit.example.test";
                claims["aud"] = "orbit-session:app:test";
                claims["sub"] = "licence";
                claims["jti"] = "session_token";
                claims["iat"] = static_cast<Json::Int64>(now);
                claims["nbf"] = static_cast<Json::Int64>(now);
                claims["exp"] = static_cast<Json::Int64>(now + 120);
                claims["application_id"] = "app";
                claims["environment_id"] = "test";
                claims["activation_id"] = "activation";
                claims["installation_id"] = input["installation_id"];
                claims["binding_mode"] = "none";
                claims["policy_version"] = 1;
                claims["entitlements"]["export"] = true;
                claims["refresh_after"] = static_cast<Json::Int64>(now + 60);
                claims["offline_allowed"] = false;
                claims["session_id"] = id;
                claims["session_sequence"] = static_cast<Json::Int64>(sequence);
                const auto token = sign_test_token(claims, "orbit-session+jwt", "test-key");
                Json::Value response(Json::objectValue);
                response["session_id"] = id;
                response["sequence"] = static_cast<Json::Int64>(sequence);
                response["expires_at"] = "2027-01-15T08:02:00Z";
                response["server_time"] = "2027-01-15T08:00:00Z";
                // The test clock's epoch is the signed server timestamp.
                response["expires_at"] = timestamp_for_test(now + 120);
                response["server_time"] = timestamp_for_test(now);
                response["grant"] = token;
                return HttpResponse{200, encode_json(response), {}};
            }
            if (route == "/api/client/v1/activations") {
                if (activation_gate) activation_gate->block();
                ++activation_calls;
                const auto input = parse_json(body);
                require(input["installation_id"].isString() &&
                            input["installation_id"].asString().size() >= 16,
                        "activation installation mismatch");
                require(input["application_id"].asString() == "app" && input["environment_id"].asString() == "test",
                        "activation scope missing");
                const auto installation = input["installation_id"].asString();
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    last_activation_idempotency = input["idempotency_key"].asString();
                    last_previous_credential = input["previous_credential"].isString()
                        ? input["previous_credential"].asString() : std::string{};
                }
                if (input["credential_mode"] == "persistent") persistent_mode = true;
                if (activation_response_lost.load()) return HttpResponse{503, "{}", {}};
                if (malformed_activation.load()) return HttpResponse{200, R"({"bad":true})", {}};
                auto reply = activation_reply(corpus, offline_activation.load(), installation,
                    persistent_mode.load() && !finite_persistent_response.load());
                if (floating_session.load()) {
                    reply["grant"] = Json::Value(Json::nullValue);
                    reply["session_required"] = true;
                    reply["licence_id"] = "licence";
                }
                if (missing_expiry.load()) reply.removeMember("credential_expires_at");
                if (pre_epoch_server_time.load()) reply["server_time"] = "1969-12-31T23:59:59Z";
                return HttpResponse{200, encode_json(reply), {}};
            }
            if (route.find("/api/client/v1/activations/") == 0 && route.find("/validate") != std::string_view::npos) {
                ++validate_calls;
                if (offline_refresh.load()) return HttpResponse{503, "{}", "0"};
                if (tls_failure_refresh.load()) raise(ErrorKind::transport_security, "transport_security");
                Json::Value input_value = parse_json(body);
                const auto installation = input_value["installation_id"].asString();
                auto reply = activation_reply(corpus, offline_activation.load(), installation,
                                              persistent_mode.load(), false);
                if (floating_session.load()) {
                    reply["grant"] = Json::Value(Json::nullValue);
                    reply["session_required"] = true;
                    reply["licence_id"] = "licence";
                }
                return HttpResponse{200, encode_json(reply), {}};
            }
            if (route == "/api/client/v1/sessions") {
                if (sessions_gate) sessions_gate->block();
                require(method == "POST", "login method mismatch");
                if (login_denied.load()) {
                    return HttpResponse{403,
                        R"({"error":{"code":"invalid_credentials","message":"Invalid credentials","request_id":"login_1"}})", {}};
                }
                Json::Value value(Json::objectValue);
                value["customer"] = Json::Value(Json::objectValue);
                value["customer"]["id"] = "customer_1";
                value["customer"]["username"] = "alice";
                value["customer"]["email"] = "alice@example.test";
                value["customer"]["suspended"] = false;
                value["customer"]["created_at"] = far_future_metadata.load()
                    ? "9999-01-01T00:00:00Z" : "2026-01-01T00:00:00Z";
                value["session"] = std::string(43, 's');
                value["expires_at"] = far_future_metadata.load()
                    ? "9999-01-01T00:00:00Z" : "2027-01-01T00:00:00Z";
                return HttpResponse{200, encode_json(value), {}};
            }
            if (route == "/api/client/v1/registrations") {
                if (registration_gate) registration_gate->block();
                Json::Value value(Json::objectValue);
                value["accepted"] = true;
                value["resend_credential"] = std::string(43, 'r');
                value["expires_at"] = far_future_metadata.load()
                    ? "9999-01-01T00:00:00Z" : "2027-01-01T00:00:00Z";
                return HttpResponse{200, encode_json(value), {}};
            }
            if (route == "/api/client/v1/registrations/resend") {
                if (resend_gate) resend_gate->block();
                return HttpResponse{200, R"({"accepted":true})", {}};
            }
            if (route == "/api/client/v1/password-recovery") {
                if (recovery_gate) recovery_gate->block();
                return HttpResponse{200, R"({"accepted":true})", {}};
            }
            if (route == "/api/client/v1/email-changes") {
                return HttpResponse{200, R"({"accepted":true})", {}};
            }
            if (route.find("/api/client/v1/licences?") == 0) {
                require(method == "GET" && bearer_value == std::string(43, 's'), "licence list authorization missing");
                Json::Value page(Json::objectValue);
                page["items"] = Json::Value(Json::arrayValue);
                auto licence = ApiFixture::sample_licence(far_future_metadata.load(), offline_file_seconds.load());
                if (omit_offline_file_seconds.load()) licence.removeMember("offline_file_seconds");
                if (omit_limit_map.load())
                    licence.removeMember(omit_limit_map == 1 ? "usage_limits" : "resource_limits");
                page["items"].append(std::move(licence));
                page["next_cursor"] = "cursor_2";
                return HttpResponse{200, encode_json(page), {}};
            }
            if (route == "/api/client/v1/licence-claims") {
                require(method == "POST" && bearer_value.empty(), "licence claim leaked bearer header");
                auto licence = ApiFixture::sample_licence(far_future_metadata.load(), offline_file_seconds.load());
                if (omit_offline_file_seconds.load()) licence.removeMember("offline_file_seconds");
                return HttpResponse{200, encode_json(licence), {}};
            }
            if (route.find("/api/client/v1/sessions/current?") == 0 && method == "DELETE") {
                if (logout_gate) logout_gate->block();
                require(bearer_value == std::string(43, 's'), "logout authorization missing");
                if (logout_error.load()) {
                    return HttpResponse{403,
                        R"({"error":{"code":"session_expired","message":"Expired","request_id":"logout_1"}})", {}};
                }
                return HttpResponse{204, {}, {}};
            }
            return HttpResponse{404, R"({"error":{"code":"not_found","message":"Not found","request_id":"request_1"}})", {}};
        };
    }

    static Json::Value sample_licence(bool far_future = false, std::int64_t file_seconds = 86400) {
        Json::Value licence(Json::objectValue);
        licence["id"] = "licence_1";
        licence["policy_name"] = "Standard";
        licence["state"] = "active";
        licence["expiry_mode"] = "never";
        licence["first_used_at"] = far_future
            ? "9999-12-31T23:59:59Z" : "2026-01-01T00:00:00Z";
        licence["expires_at"] = far_future
            ? "9999-12-31T23:59:59Z" : "2027-01-01T00:00:00Z";
        licence["duration_seconds"] = Json::Int64{3000000000LL};
        licence["device_limit"] = 1;
        licence["hwid_locked"] = false;
        licence["offline_allowed"] = true;
        licence["offline_seconds"] = 3600;
        licence["offline_file_seconds"] = static_cast<Json::Int64>(file_seconds);
        licence["usage_limits"] = Json::Value(Json::objectValue);
        licence["resource_limits"] = Json::Value(Json::objectValue);
        licence["entitlements"] = Json::Value(Json::objectValue);
        licence["entitlements"]["export"] = true;
        return licence;
    }
};

Client client_for(ApiFixture& fixture) {
    return make_test_client(config(), Transport("https://example.test", fixture.handler()), fixture.storage);
}

std::string persistent_test_path() {
    auto temporary_root = std::filesystem::temp_directory_path();
#if defined(__APPLE__)
    temporary_root = std::filesystem::canonical(temporary_root);
#endif
    return (temporary_root / ("orbit-cpp-installed-test-" + new_installation_id())).string();
}

Client persistent_client_for(ApiFixture& fixture, const std::string& path,
                             std::optional<Fingerprint> fingerprint = std::nullopt) {
    auto setup = config();
    setup.installation_id.reset();
    setup.fingerprint = std::move(fingerprint);
    if (fixture.floating_session.load()) {
        setup.session_keys = std::make_shared<const orbit::detail::SessionKeys>(
            orbit::detail::SessionKeys::parse(fixture.corpus["jwks"], "test"));
    }
    auto storage = open_installed_storage(setup, path);
    return make_test_installed_client(setup,
        Transport("https://example.test", fixture.handler()), std::move(storage));
}

struct SessionTestClock {
    std::atomic<std::int64_t> elapsed{100'000'000'000LL};
    std::atomic<std::int64_t> wall{1'700'000'000};
    SessionTestClock() {
        set_test_clock([this] { return std::make_pair(elapsed.load(), wall.load()); });
    }
    ~SessionTestClock() { set_test_clock({}); }
    void advance(std::int64_t seconds) {
        elapsed.fetch_add(seconds * 1'000'000'000LL);
        wall.fetch_add(seconds);
    }
};

void test_installed_floating_session_lifecycle(const Corpus &corpus) {
    SessionTestClock clock;
    const auto path = persistent_test_path();
    auto setup = config();
    setup.installation_id.reset();
    setup.session_keys = std::make_shared<const orbit::detail::SessionKeys>(
        orbit::detail::SessionKeys::parse(corpus.jwks, "test"));
    ApiFixture fixture(corpus.value);
    fixture.floating_session = true;
    fixture.fail_first_session_start = true;
    auto storage = open_installed_storage(setup, path);
    fixture.before_session_start = [&] {
        const auto bytes = storage->load();
        require(bytes.has_value(), "floating credential must be saved before session acquisition");
        const auto record = persistent_codec::decode(setup, storage->provider(), *bytes);
        require(!record["credential"].isNull() && record["access"].isNull(),
                "floating activation must persist credential without cached access "
                "before seat request");
    };
    auto client =
        open_installed_state(setup, Transport("https://example.test", fixture.handler()), storage);
    std::atomic_bool cancelled{false};
    try {
        const auto activated =
            client->activate("floating-key", "floating-operation-123", std::nullopt, cancelled);
        require(activated.access == Access::online && activated.session &&
                    activated.session->sequence == 1 && fixture.session_start_calls == 2,
                "activation must acquire a floating seat and retry an uncertain "
                "start with the same ID");
        {
            std::lock_guard<std::mutex> lock(fixture.mutex);
            require(fixture.session_ids.size() == 2 &&
                        fixture.session_ids[0] == fixture.session_ids[1],
                    "a lost session start acknowledgement must reuse its ID");
        }
        const auto requests_before = [&] {
            std::lock_guard<std::mutex> lock(fixture.mutex);
            return fixture.requests.size();
        }();
        require(
            client->require_access("export", cancelled).session->sequence == 1 &&
                client->start_session(cancelled).session->sequence == 1 &&
                requests_before ==
                    [&] {
                        std::lock_guard<std::mutex> lock(fixture.mutex);
                        return fixture.requests.size();
                    }(),
            "warm guards and repeated start must reuse a valid seat without HTTP");

        clock.advance(60);
        const auto renewed = client->refresh(cancelled);
        require(renewed.access == Access::online && renewed.session &&
                    renewed.session->sequence == 2 && fixture.session_renew_calls == 1,
                "floating refresh must renew exactly the next sequence");
        {
            std::lock_guard<std::mutex> lock(fixture.mutex);
            require(fixture.session_sequences == std::vector<std::int64_t>{2},
                    "renewal must use the last accepted sequence plus one");
        }

        const auto starts_before_end = fixture.session_start_calls.load();
        const auto ended = client->end_session(cancelled);
        require(!ended.session && ended.access != Access::online && fixture.session_end_calls == 1,
                "end_session must clear local authority and release the server seat");
        expect_error([&] { (void)client->require_access("export", cancelled); }, ErrorKind::denied);
        require(fixture.session_start_calls == starts_before_end,
                "a guard after explicit end must not reacquire automatically");
        const auto restarted = client->start_session(cancelled);
        require(restarted.access == Access::online && restarted.session &&
                    restarted.session->sequence == 1 &&
                    fixture.session_start_calls == starts_before_end + 1,
                "explicit start must acquire a fresh session after end");
        const auto prior_id = restarted.session->id;
        client->close();
        client.reset();
        fixture.before_session_start = {};
        storage.reset();

        ApiFixture reopened(corpus.value);
        reopened.floating_session = true;
        reopened.persistent_mode = true;
        auto next_storage = open_installed_storage(setup, path);
        auto reopened_client = open_installed_state(
            setup, Transport("https://example.test", reopened.handler()), next_storage);
        try {
            const auto after_restart = reopened_client->snapshot();
            require(after_restart.access == Access::online && after_restart.session &&
                        after_restart.session->sequence == 1 &&
                        after_restart.session->id != prior_id && reopened.session_start_calls == 1,
                    "restart must validate the saved credential and acquire a fresh "
                    "non-restored session");
            reopened_client->close();
            reopened_client.reset();
        } catch (...) {
            reopened_client->close();
            reopened_client.reset();
            throw;
        }
    } catch (...) {
        if (client) {
            client->close();
            client.reset();
        }
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
        throw;
    }
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
}

void test_floating_session_failures_and_generation_fences(const Corpus &corpus) {
    SessionTestClock clock;
    auto make_state = [&](ApiFixture &fixture, const std::string &path) {
        auto setup = config();
        setup.installation_id.reset();
        setup.session_keys = std::make_shared<const orbit::detail::SessionKeys>(
            orbit::detail::SessionKeys::parse(corpus.jwks, "test"));
        fixture.floating_session = true;
        return open_installed_state(setup, Transport("https://example.test", fixture.handler()),
                                    open_installed_storage(setup, path));
    };

    {
        const auto path = persistent_test_path();
        ApiFixture fixture(corpus.value);
        auto state = make_state(fixture, path);
        std::atomic_bool cancelled{false};
        std::atomic_int result{-1};
        fixture.activation_gate = std::make_shared<Gate>();
        std::thread activation([&] {
            try {
                (void)state->activate("floating-key", "initial-end-operation", std::nullopt,
                                      cancelled);
            } catch (const Error &error) {
                result = static_cast<int>(error.kind());
            }
        });
        fixture.activation_gate->wait_until_entered();
        (void)state->end_session(cancelled);
        fixture.activation_gate->release();
        activation.join();
        require(result == static_cast<int>(ErrorKind::stale_response) &&
                    state->snapshot().access != Access::online && fixture.session_start_calls == 0,
                "late initial activation must not undo end_session");
        fixture.activation_gate.reset();
        (void)state->activate("floating-key", "initial-end-operation", std::nullopt, cancelled);
        require(state->snapshot().access == Access::online,
                "later explicit activation must restore access");
        const auto previous_session = state->snapshot().session->id;
        (void)state->activate("replacement-key", "replacement-operation", std::nullopt, cancelled);
        require(state->snapshot().session && state->snapshot().session->id != previous_session,
                "replacement activation must never inherit the old session grant");

        (void)state->end_session(cancelled);
        reset_access_benchmark_metrics();
        set_access_benchmark_invalidation_counting(true);
        state->wake_worker();
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        const auto ended_checks = access_benchmark_invalidation_checks();
        set_access_benchmark_invalidation_counting(false);
        require(ended_checks < 20, "explicitly ended session must not spin the worker");
        (void)state->start_session(cancelled);

        fixture.jwks_gate = std::make_shared<Gate>();
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->config.session_keys.reset();
        }
        clock.advance(60);
        result = -1;
        std::thread renewal([&] {
            try {
                (void)state->refresh(cancelled);
            } catch (const Error &error) {
                result = static_cast<int>(error.kind());
            }
        });
        fixture.jwks_gate->wait_until_entered();
        state->local_logout();
        fixture.jwks_gate->release();
        renewal.join();
        require(result == static_cast<int>(ErrorKind::stale_response) &&
                    state->snapshot().access == Access::denied,
                "verification after blocked JWKS must use a fenced immutable profile");
        state->close();
        state.reset();
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }

    {
        const auto path = persistent_test_path();
        ApiFixture outage(corpus.value);
        auto state = make_state(outage, path);
        std::atomic_bool cancelled{false};
        (void)state->activate("floating-key", "outage-operation-123", std::nullopt, cancelled);
        const auto initial = state->snapshot();
        clock.advance(60);
        outage.session_renew_failures = 3;
        const auto retained = state->refresh(cancelled);
        require(retained.access == Access::online && retained.session &&
                    retained.session->id == initial.session->id &&
                    retained.session->sequence == 1 && outage.session_renew_calls == 3,
                "a transient outage may retain only the still-valid signed interval");
        clock.advance(60);
        require(state->snapshot().access == Access::expired,
                "session authority must expire exactly at the signed deadline");
        expect_error([&] { (void)state->require_access("export", cancelled); }, ErrorKind::denied);
        require(state->snapshot().access == Access::expired,
                "expired session guards cannot return success while a retry is "
                "delayed");
        outage.deny_session_start = true;
        expect_error([&] { (void)state->start_session(cancelled); }, ErrorKind::denied);
        std::string first_dead_id;
        {
            std::lock_guard<std::mutex> lock(outage.mutex);
            first_dead_id = outage.session_ids.back();
        }
        expect_error([&] { (void)state->start_session(cancelled); }, ErrorKind::denied);
        {
            std::lock_guard<std::mutex> lock(outage.mutex);
            require(outage.session_ids.back() != first_dead_id,
                    "a definitive sequence conflict must not pin retries to one dead "
                    "session ID");
        }
        state->close();
        state.reset();
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }

    {
        const auto path = persistent_test_path();
        ApiFixture denied(corpus.value);
        auto state = make_state(denied, path);
        std::atomic_bool cancelled{false};
        (void)state->activate("floating-key", "denial-operation-123", std::nullopt, cancelled);
        denied.deny_session_renewal = true;
        denied.deny_session_start = true;
        clock.advance(60);
        try {
            (void)state->refresh(cancelled);
        } catch (const Error &error) {
            require(error.kind() == ErrorKind::denied,
                    "session renewal denial had the wrong error kind");
        }
        require(!state->snapshot().session && state->snapshot().access != Access::online,
                "an authoritative renewal denial must immediately clear current "
                "local authority");
        int prompts = 0;
        expect_error(
            [&] {
                (void)state->require_access("export", cancelled);
                // The public prompt API is exercised below with the same denied path.
            },
            ErrorKind::denied);
        auto public_client = make_test_client_from_state(state);
        expect_error(
            [&] {
                (void)public_client.ensure_access("export", [&]() -> std::optional<std::string> {
                    ++prompts;
                    return "must-not-prompt";
                });
            },
            ErrorKind::denied);
        require(prompts == 0, "floating renewal denial must never prompt for a licence key");
        state->close();
        state.reset();
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }

    for (const bool denied_reply : {false, true}) {
        const auto path = persistent_test_path();
        ApiFixture fixture(corpus.value);
        auto state = make_state(fixture, path);
        std::atomic_bool cancelled{false};
        (void)state->activate("floating-key", "fence-operation-123", std::nullopt, cancelled);
        clock.advance(60);
        fixture.session_gate = std::make_shared<Gate>();
        std::atomic_int result{-1};
        std::thread worker([&] {
            try {
                (void)state->refresh(cancelled);
            } catch (const Error &error) {
                result.store(static_cast<int>(error.kind()));
            }
        });
        fixture.session_gate->wait_until_entered();
        if (denied_reply)
            fixture.deny_session_renewal = true;
        state->local_logout();
        fixture.session_gate->release();
        worker.join();
        // The background worker may be the request held at the gate; this
        // thread then observes the logout itself instead of a stale reply.
        require((result == static_cast<int>(ErrorKind::stale_response) ||
                 result == static_cast<int>(ErrorKind::reauthentication_required)) &&
                    state->snapshot().access == Access::denied,
                "late session success or renewal denial must not cross logout "
                "generation fencing");
        state->close();
        state.reset();
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
    for (const auto action : {"end", "close", "cancel"}) {
        for (const bool denied_reply : {false, true}) {
            const auto path = persistent_test_path();
            ApiFixture fixture(corpus.value);
            auto state = make_state(fixture, path);
            std::atomic_bool cancelled{false}, ready{false};
            (void)state->activate("floating-key", "start-fence-operation", std::nullopt, ready);
            (void)state->end_session(ready);
            fixture.session_gate = std::make_shared<Gate>();
            std::atomic_bool accepted{false};
            std::thread request([&] {
                try {
                    (void)state->start_session(cancelled);
                    accepted = true;
                } catch (const Error &) {
                }
            });
            fixture.session_gate->wait_until_entered();
            fixture.deny_session_start = denied_reply;
            const auto generation_before = state->generation();
            std::thread transition;
            if (std::string_view(action) == "end") {
                transition = std::thread([&] {
                    try {
                        (void)state->end_session(ready);
                    } catch (const Error &) {
                    }
                });
                for (unsigned attempt = 0;
                     attempt < 1000 && state->generation() == generation_before; ++attempt)
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
            } else if (std::string_view(action) == "close") {
                transition = std::thread([&] { state->close(); });
                for (unsigned attempt = 0; attempt < 1000 && !state->owner_cancelled->load();
                     ++attempt)
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
            } else
                cancelled = true;
            fixture.session_gate->release();
            request.join();
            if (transition.joinable())
                transition.join();
            require(!accepted, "blocked session start crossed end, close or cancellation");
            if (std::string_view(action) != "close")
                require(state->snapshot().access != Access::online,
                        "blocked reply restored authority");
            state->close();
            state.reset();
            std::error_code ignored;
            std::filesystem::remove_all(path, ignored);
        }
    }
    {
        const auto path = persistent_test_path();
        ApiFixture fixture(corpus.value);
        auto state = make_state(fixture, path);
        std::atomic_bool ready{false};
        (void)state->activate("floating-key", "unknown-end-operation", std::nullopt, ready);
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->session_profile_known = false;
            state->session_required = false;
        }
        const auto starts = fixture.session_start_calls.load();
        (void)state->end_session(ready);
        expect_error([&] { (void)state->require_access("export", ready); }, ErrorKind::denied);
        require(fixture.session_start_calls == starts,
                "unknown-policy end acquired a floating session");
        state->close();
        state.reset();
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
}

std::string offline_file(const AppKey &app_key, std::string_view installation,
                         std::int64_t sequence, std::string_view issuance, std::int64_t issued,
                         std::int64_t expires, bool export_feature = true) {
    Json::Value claims(Json::objectValue);
    claims["ver"] = 1;
    claims["iss"] = app_key.issuer();
    claims["aud"] = "orbit-offline:" + app_key.application_id() + ":" + app_key.environment_id();
    claims["sub"] = "licence";
    claims["jti"] = std::string(issuance);
    claims["iat"] = static_cast<Json::Int64>(issued);
    claims["nbf"] = static_cast<Json::Int64>(issued);
    claims["exp"] = static_cast<Json::Int64>(expires);
    claims["application_id"] = app_key.application_id();
    claims["environment_id"] = app_key.environment_id();
    claims["activation_id"] = "activation";
    claims["installation_id"] = std::string(installation);
    claims["sequence"] = static_cast<Json::Int64>(sequence);
    claims["binding_mode"] = "none";
    claims["policy_version"] = 1;
    claims["entitlements"] = Json::Value(Json::objectValue);
    claims["entitlements"]["export"] = export_feature;
    return sign_test_token(claims, "orbit-offline+jwt", "offline-test-fixture");
}

void test_online_meters_and_updates(const Corpus &corpus) {
    ApiFixture fixture(corpus.value);
    auto base = fixture.handler();
    int mode = 0, calls = 0;
    std::string operation;
    auto artifact = parse_json(
        R"({"id":"artifact","release_id":"release","platform":"linux","architecture":"x64","filename":"app.bin","byte_length":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","delivery_mode":"public","url":"https://download.example.test/file","required_feature":null})");
    auto handler = [&](std::string_view method, std::string_view url, std::string_view bearer,
                       std::string_view body, const CancellationView &cancelled) -> HttpResponse {
        const auto input = body.empty() ? Json::Value{} : parse_json(body);
        if (url.find("/usage/") != std::string_view::npos) {
            require(input["credential"].isString() && input["installation_id"].isString(),
                    "missing activation proof");
            ++calls;
            const auto id = input["idempotency_key"].asString();
            if (operation.empty())
                operation = id;
            require(id == operation, "mutation transport retries changed operation ID");
            if (mode == 0 && calls == 1)
                return {503, "{}", {}};
            auto counter = parse_json(
                R"({"name":"exports","period":"lifetime","limit":5,"used":2,"remaining":3,"period_started_at":null,"resets_at":null})");
            if ((mode >= 1 && mode <= 3) || mode == 9) {
                if (mode != 9) {
                    counter["used"] = 4;
                    counter["remaining"] = 1;
                }
                if (mode == 2)
                    counter["remaining"] = 5;
                auto error = parse_json(
                    R"({"error":{"code":"usage_limit_reached","message":"Limit","request_id":"fixture"}})");
                error["error"]["counter"] = counter;
                error["error"]["requested_units"] = 2;
                error["error"]["idempotency_key"] = mode == 3 ? "different_operation" : id;
                return {409, encode_json(error), {}};
            }
            counter["idempotency_key"] = id;
            counter["consumed_units"] = 2;
            if (mode == 4)
                counter["used"] = Json::Int64(9007199254740992LL);
            if (mode == 8) {
                counter["used"] = 0;
                counter["remaining"] = 5;
            }
            return {200, encode_json(counter), {}};
        }
        if (url.find("/resources/") != std::string_view::npos) {
            auto result = parse_json(
                R"({"name":"projects","limit":5,"used":1,"remaining":4,"allocation_id":"allocation_one","resource_id":"project_one","units":1,"state":"released"})");
            result["idempotency_key"] = input["idempotency_key"];
            if (mode == 10) {
                result["state"] = "active";
                result["used"] = 0;
                result["remaining"] = 5;
            }
            return {200, encode_json(result), {}};
        }
        if (url.find("/updates") != std::string_view::npos) {
            require(input["channel"] == "stable", "update channel must default to stable");
            if (mode == 6)
                return {200, R"({"release":null,"artifact":null})", {}};
            auto release = parse_json(
                R"({"id":"release","channel":"stable","version":"1.2","notes":"Changes","release_number":2,"state":"published","created_at":"2026-09-27T00:00:00.123456Z","published_at":"2026-09-27T00:00:00Z","artifacts":[]})");
            release["artifacts"].append(artifact);
            if (mode == 7)
                release["artifacts"].append(artifact);
            Json::Value result(Json::objectValue);
            result["release"] = release;
            result["artifact"] = artifact;
            return {200, encode_json(result), {}};
        }
        if (url.find("/downloads/authorize") != std::string_view::npos) {
            Json::Value result(Json::objectValue);
            result["artifact"] = artifact;
            result["ticket"] = Json::nullValue;
            result["expires_at"] = Json::nullValue;
            return {200, encode_json(result), {}};
        }
        return base(method, url, bearer, body, cancelled);
    };
    auto client =
        make_test_client(config(), Transport("https://example.test", handler), fixture.storage);
    (void)client.activate("synthetic-key");
    auto consumed = client.consume("exports", 2);
    require(calls == 2 && consumed.counter.used == 2 && consumed.idempotency_key == operation,
            "lost response retry must keep typed consumption and original ID");
    for (const auto test_mode : {1, 2, 3, 4, 8, 9}) {
        mode = test_mode;
        try {
            (void)client.consume("exports", 2, operation);
            throw std::runtime_error("invalid consume accepted");
        } catch (const OperationError &error) {
            require(error.operation_id() == operation &&
                        error.kind() ==
                            (mode == 1 ? ErrorKind::denied : ErrorKind::invalid_response),
                    "uncertain mutation lost ID");
            require(mode == 1 ? error.usage_counter() && error.usage_counter()->remaining == 1
                              : !error.usage_counter(),
                    "unvalidated capacity denial escaped");
        }
    }
    mode = 0;
    auto allocated = client.acquire_resource("projects", "project_one");
    require(allocated.state == AllocationState::released && allocated.counter.used == 1,
            "acquire replay must retain released allocation and current counter");
    require(client.release_resource("projects", allocated.allocation_id).state ==
                AllocationState::released,
            "release must return a released allocation");
    expect_error([&] { (void)client.consume("exports", 0); }, ErrorKind::configuration);
    mode = 10;
    expect_error([&] { (void)client.acquire_resource("projects", "project_one"); },
                 ErrorKind::invalid_response);
    mode = 5;
    auto update = client.check_for_update(1, "stable", UpdateTarget{"linux", "x64"});
    require(update && update->release.release_number == 2 && update->release.artifacts.size() == 1,
            "update must expose one exact target");
    require(!client.authorize_download("release", "artifact").ticket,
            "public download must not have a ticket");
    mode = 6;
    require(!client.check_for_update(1), "empty update must be optional");
    mode = 7;
    expect_error([&] { (void)client.check_for_update(1, "stable", UpdateTarget{"linux", "x64"}); },
                 ErrorKind::invalid_response);
    mode = 5;
    expect_error(
        [&] { (void)client.check_for_update(1, "stable", UpdateTarget{"linux", "arm64"}); },
        ErrorKind::invalid_response);
    client.close();
}

struct FakeClock {
    std::atomic<std::int64_t> elapsed{100'000'000'000LL};
    std::atomic<std::int64_t> wall{1'700'000'000};
    FakeClock() {
        auto self = this;
        set_test_clock([self] { return std::make_pair(self->elapsed.load(), self->wall.load()); });
    }
    ~FakeClock() { set_test_clock({}); }
    void advance(std::int64_t seconds) {
        elapsed.fetch_add(seconds * 1'000'000'000LL);
        wall.fetch_add(seconds);
    }
};

template <class Predicate> bool wait_for_condition(Predicate predicate);

void test_installed_offline_file_lifecycle(const Corpus &corpus) {
    std::ifstream offline_input(ORBIT_OFFLINE_VECTORS_PATH, std::ios::binary);
    require(offline_input.good(), "offline test vector file is unavailable");
    const std::string offline_bytes((std::istreambuf_iterator<char>(offline_input)), {});
    const auto offline_corpus = parse_json(offline_bytes, 2 * 1024 * 1024);
    const auto trusted = std::make_shared<const orbit::detail::OfflineKeys>(
        orbit::detail::OfflineKeys::parse(offline_corpus["jwks"], "test"));
    const auto app_key = AppKey::parse(
        "orbit_app_test_" +
        base64url_encode(reinterpret_cast<const unsigned char *>("https://orbit.example.test"),
                         std::string_view("https://orbit.example.test").size()) +
        ".app.test");
    require(app_key.public_key() ==
                "orbit_app_test_" +
                    base64url_encode(
                        reinterpret_cast<const unsigned char *>("https://orbit.example.test"),
                        std::string_view("https://orbit.example.test").size()) +
                    ".app.test",
            "public app-key serialization must round trip exactly");

    constexpr std::int64_t issued = 1800000000;
    std::atomic<std::int64_t> elapsed{1000000000};
    std::atomic<std::int64_t> wall{issued};
    set_test_clock([&] { return std::pair{elapsed.load(), wall.load()}; });
    const auto path = persistent_test_path();
    auto make_client = [&](ApiFixture &fixture, bool include_keys = true) {
        auto setup = config();
        setup.installation_id.reset();
        setup.public_app_key = app_key.public_key();
        if (include_keys)
            setup.offline_keys = trusted;
        auto storage = open_installed_storage(setup, path);
        return make_test_installed_client(setup,
            Transport("https://example.test", fixture.handler()), std::move(storage));
    };
    auto inspect_record = [&] {
        auto setup = config();
        setup.installation_id.reset();
        auto storage = open_installed_storage(setup, path);
        const auto bytes = storage->load();
        require(bytes.has_value(), "offline installed record disappeared");
        return persistent_codec::decode(setup, storage->provider(), *bytes);
    };
    try {
        std::string installation;
        std::string first;
        std::string renewed;
        {
            ApiFixture fixture(corpus.value);
            auto client = make_client(fixture);
            const auto request = client.offline_request();
            installation = request.installation_id;
            const auto request_json = parse_json(request.to_json());
            require(request_json["format"] == "orbit-offline-request" &&
                        request_json["version"] == 1 &&
                        request_json["app_key"] == app_key.public_key() &&
                        request_json["installation_id"] == installation &&
                        request_json["fingerprint"].isNull() &&
                        request_json["fingerprint_provider"].isNull(),
                    "offline request must serialize stable scope and null binding "
                    "fields");
            first = offline_file(app_key, installation, 1, "offline_issue_1", issued, issued + 120);
            const auto imported = client.import_offline_file(" \t" + first + "\n");
            require(imported.access == Access::offline && imported.offline_file_mode &&
                        imported.has_feature("export") && imported.expires_at &&
                        imported.expires_at->time_since_epoch().count() == issued + 120,
                    "offline file import must expose only signed typed metadata");
            require(client.require_access("export").access == Access::offline,
                    "offline file must authorize its signed feature without HTTP");
            auto missing = expect_error([&] { (void)client.require_access("missing"); },
                                        ErrorKind::feature_unavailable);
            require(missing.code() == "feature_unavailable",
                    "offline feature denial lost its typed code");
            require(fixture.requests.empty(), "offline file request/guard made an HTTP request");
            const auto conflict = offline_file(app_key, installation, 1, "offline_issue_conflict",
                                               issued, issued + 120, false);
            const auto sequence_error = expect_error(
                [&] { (void)client.import_offline_file(conflict); }, ErrorKind::denied);
            require(sequence_error.code() == "offline_sequence",
                    "equal-sequence conflict was not rejected");
            require(client.import_offline_file(first).access == Access::offline,
                    "exact equal-sequence reimport should be idempotent");
            elapsed.fetch_add(500000000);
            (void)client.import_offline_file(first);
            elapsed.fetch_add(500000000);
            require(client.import_offline_file(first).remaining_offline ==
                        std::chrono::seconds(119),
                    "reimport must count fractional elapsed time exactly once");
            require(client.import_offline_file(first).remaining_offline ==
                        std::chrono::seconds(119),
                    "reimport without elapsed time must not move the deadline");
            Cancellation cancelled;
            cancelled.cancel();
            const auto cancelled_error = expect_error(
                [&] { (void)client.import_offline_file(first, &cancelled); }, ErrorKind::cancelled);
            require(cancelled_error.code() == "cancelled" && fixture.requests.empty(),
                    "cancelled import changed access or made a request");
            client.close();
            const auto saved = inspect_record();
            require(saved["format"] == 3 && saved["offline"]["jws"] == first &&
                        saved["offline"]["sequence"] == 1 && saved["credential"].isNull() &&
                        saved["access"].isNull() && saved["pending_activation"].isNull(),
                    "offline import must durably store one authority without online "
                    "access");
        }
        {
            ApiFixture missing_keys(corpus.value);
            expect_error([&] { (void)make_client(missing_keys, false); }, ErrorKind::configuration);
            require(missing_keys.requests.empty() && inspect_record()["offline"]["jws"] == first,
                    "missing trusted keys must preserve an active signed file "
                    "without HTTP");
        }
        wall.store(issued + 121);
        elapsed.store(2000000000);
        {
            ApiFixture restarted(corpus.value);
            auto client = make_client(restarted);
            const auto expired = client.snapshot();
            require(expired.access == Access::expired && expired.offline_file_mode &&
                        expired.expires_at &&
                        expired.expires_at->time_since_epoch().count() == issued + 120,
                    "restart downtime must count toward absolute file expiry");
            const auto expired_error =
                expect_error([&] { (void)client.require_access("export"); }, ErrorKind::denied);
            int prompts = 0;
            expect_error(
                [&] {
                    (void)client.ensure_access("export", [&]() -> std::optional<std::string> {
                        ++prompts;
                        return "unexpected-key";
                    });
                },
                ErrorKind::denied);
            require(expired_error.code() == "offline_file_expired" && restarted.requests.empty(),
                    "expired file must not prompt or validate online");
            require(prompts == 0, "expired file access must never prompt for an activation key");
            const auto renewal_issued = wall.load() + 2;
            renewed = offline_file(app_key, installation, 2, "offline_issue_2", renewal_issued,
                                   renewal_issued + 240);
            require(client.import_offline_file(renewed).remaining_offline ==
                            std::chrono::seconds(240) &&
                        restarted.requests.empty(),
                    "future-skewed renewal must advance the original anchor only to "
                    "the signed time floor");
            require(client.import_offline_file(renewed).remaining_offline ==
                        std::chrono::seconds(240),
                    "repeating a future-skewed renewal without elapsed time must not "
                    "move its deadline");
            elapsed.fetch_add(4000000000LL);
            wall.fetch_add(4);
            require(client.import_offline_file(renewed).remaining_offline ==
                        std::chrono::seconds(236),
                    "a renewed file must count whole elapsed seconds exactly once");
            expect_error([&] { (void)client.import_offline_file(first); },
                         ErrorKind::invalid_response);
            wall.store(issued + 200);
            elapsed.store(81000000000LL);
            client.logout();
            require(client.snapshot().access == Access::denied,
                    "logout retained offline authority");
            elapsed.fetch_add(121000000000LL);
            const auto frozen_clock = expect_error([&] { (void)client.import_offline_file(first); },
                                                   ErrorKind::clock_uncertain);
            require(frozen_clock.code() == "clock_uncertain" && restarted.requests.empty(),
                    "offline anchor and floors must survive logout without accepting "
                    "a frozen-wall replay");
            client.close();
        }
        const auto after_logout = inspect_record();
        require(after_logout["format"] == 3 && after_logout["offline"]["jws"].isNull() &&
                    after_logout["offline"]["sequence"] == 2 &&
                    after_logout["offline"]["time_high_water"].asInt64() >= issued + 200 &&
                    after_logout["offline"]["wall_high_water"].asInt64() >= issued + 200,
                "logout must clear authority while retaining renewal and clock floors");
    } catch (...) {
        set_test_clock({});
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
        throw;
    }
    set_test_clock({});
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
}

void test_offline_transition_floors(const Corpus& corpus) {
    std::ifstream offline_input(ORBIT_OFFLINE_VECTORS_PATH, std::ios::binary);
    require(offline_input.good(), "offline test vector file is unavailable");
    const auto offline_corpus = parse_json(
        std::string((std::istreambuf_iterator<char>(offline_input)), {}), 2 * 1024 * 1024);
    const auto trusted = std::make_shared<const orbit::detail::OfflineKeys>(
        orbit::detail::OfflineKeys::parse(offline_corpus["jwks"], "test"));
    const auto app_key = AppKey::parse(
        "orbit_app_test_" + base64url_encode(
            reinterpret_cast<const unsigned char*>("https://orbit.example.test"),
            std::string_view("https://orbit.example.test").size()) + ".app.test");

    for (const bool account_transition : {false, true}) {
        constexpr std::int64_t issued = 1700000000;
        FakeClock clock;
        clock.wall = issued;
        const auto path = persistent_test_path();
        auto setup = config();
        setup.installation_id.reset();
        setup.public_app_key = app_key.public_key();
        setup.offline_keys = trusted;
        ApiFixture fixture(corpus.value);
        auto state = open_installed_state(setup,
            Transport("https://example.test", fixture.handler()), open_installed_storage(setup, path));
        try {
            const auto request = state->offline_request();
            const auto file = offline_file(app_key, request.installation_id, 1,
                account_transition ? "offline_account_transition" : "offline_online_transition",
                issued, issued + 120);
            std::atomic_bool cancelled{false};
            require(state->import_offline_file(file, cancelled).access == Access::offline,
                    "initial transition-floor file import failed");
            if (account_transition) {
                (void)state->login("alice", "synthetic-password", cancelled);
                state->account_logout(cancelled);
            } else {
                (void)state->activate("transition-key", {}, std::nullopt, cancelled);
            }
            state->local_logout();
            clock.advance(7);
            require(state->import_offline_file(file, cancelled).remaining_offline == std::chrono::seconds(113),
                    "a transition must retain the original offline anchor and report exact remaining time");
            require(state->import_offline_file(file, cancelled).remaining_offline == std::chrono::seconds(113),
                    "a repeated post-transition import must not move the offline deadline");
            clock.advance(2);
            require(state->import_offline_file(file, cancelled).remaining_offline == std::chrono::seconds(111),
                    "a post-transition import must count whole elapsed seconds exactly once");
            state->local_logout();
            const auto request_count = [&] {
                std::lock_guard<std::mutex> lock(fixture.mutex);
                return fixture.requests.size();
            };
            const auto requests_before = request_count();
            clock.elapsed.fetch_add(121000000000LL);
            expect_error([&] { (void)state->import_offline_file(file, cancelled); },
                         ErrorKind::clock_uncertain);
            require(request_count() == requests_before && !state->offline &&
                        state->offline_clock && state->offline_clock->time_high_water >= issued + 9,
                    "account or online transitions must keep offline time evidence without restoring authority");
            state->close();
            state.reset();
            auto saved = open_installed_storage(setup, path);
            const auto bytes = saved->load();
            require(bytes.has_value(), "transition floor record disappeared");
            const auto record = persistent_codec::decode(setup, saved->provider(), *bytes);
            require(record["offline"]["jws"].isNull() &&
                        record["offline"]["sequence"] == 1 &&
                        record["offline"]["time_high_water"].asInt64() >= issued + 9 &&
                        record["offline"]["wall_high_water"].asInt64() >= issued + 9 &&
                        record["credential"].isNull() && record["access"].isNull(),
                    "transitions must durably clear authority while retaining the offline replay floor");
        } catch (...) {
            state->close();
            state.reset();
            std::error_code ignored;
            std::filesystem::remove_all(path, ignored);
            throw;
        }
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
}

void test_offline_identity_change_clears_file(const Corpus& corpus) {
    FakeClock clock;
    constexpr std::int64_t issued = 1700000000;
    clock.wall = issued;
    std::ifstream offline_input(ORBIT_OFFLINE_VECTORS_PATH, std::ios::binary);
    require(offline_input.good(), "offline test vector file is unavailable");
    const auto offline_corpus = parse_json(
        std::string((std::istreambuf_iterator<char>(offline_input)), {}), 2 * 1024 * 1024);
    const auto trusted = std::make_shared<const orbit::detail::OfflineKeys>(
        orbit::detail::OfflineKeys::parse(offline_corpus["jwks"], "test"));
    const auto app_key = AppKey::parse(
        "orbit_app_test_" + base64url_encode(
            reinterpret_cast<const unsigned char*>("https://orbit.example.test"),
            std::string_view("https://orbit.example.test").size()) + ".app.test");
    const auto path = persistent_test_path();
    std::string original_id;
    {
        auto setup = config();
        setup.installation_id.reset();
        setup.public_app_key = app_key.public_key();
        setup.offline_keys = trusted;
        ApiFixture fixture(corpus.value);
        auto state = open_installed_state(setup,
            Transport("https://example.test", fixture.handler()), open_installed_storage(setup, path));
        original_id = state->offline_request().installation_id;
        std::atomic_bool cancelled{false};
        const auto file = offline_file(app_key, original_id, 1, "offline_identity_change",
            issued, issued + 120);
        require(state->import_offline_file(file, cancelled).access == Access::offline,
                "identity-change offline setup failed");
        state->close();
    }
    auto changed_setup = config();
    changed_setup.installation_id.reset();
    changed_setup.public_app_key = app_key.public_key();
    changed_setup.offline_keys = trusted;
    changed_setup.fingerprint = Fingerprint{std::string(64, 'a'), "custom:fixture"};
    ApiFixture changed(corpus.value);
    auto state = open_installed_state(changed_setup,
        Transport("https://example.test", changed.handler()), open_installed_storage(changed_setup, path));
    const auto changed_request = state->offline_request();
    const auto no_network_requests = [&] {
        std::lock_guard<std::mutex> lock(changed.mutex);
        return changed.requests.empty();
    };
    require(changed_request.installation_id != original_id && !state->offline &&
                state->snapshot().access == Access::denied && no_network_requests(),
            "machine identity change must rotate installation and clear offline authority without HTTP");
    state->close();
    auto installed = open_installed_storage(changed_setup, path);
    const auto bytes = installed->load();
    require(bytes.has_value(), "identity-change storage record disappeared");
    const auto record = persistent_codec::decode(changed_setup, installed->provider(), *bytes);
    require(record["installation"]["id"] == changed_request.installation_id &&
                record["offline"].isNull() && record["credential"].isNull() && record["access"].isNull(),
            "identity change must persist fresh installation identity without old offline floors");
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
}

void test_offline_activation_logout_race(const Corpus& corpus) {
    FakeClock clock;
    constexpr std::int64_t issued = 1700000000;
    clock.wall = issued;
    std::ifstream offline_input(ORBIT_OFFLINE_VECTORS_PATH, std::ios::binary);
    require(offline_input.good(), "offline test vector file is unavailable");
    const auto offline_corpus = parse_json(
        std::string((std::istreambuf_iterator<char>(offline_input)), {}), 2 * 1024 * 1024);
    const auto trusted = std::make_shared<const orbit::detail::OfflineKeys>(
        orbit::detail::OfflineKeys::parse(offline_corpus["jwks"], "test"));
    const auto app_key = AppKey::parse(
        "orbit_app_test_" + base64url_encode(
            reinterpret_cast<const unsigned char*>("https://orbit.example.test"),
            std::string_view("https://orbit.example.test").size()) + ".app.test");
    const auto path = persistent_test_path();
    auto setup = config();
    setup.installation_id.reset();
    setup.public_app_key = app_key.public_key();
    setup.offline_keys = trusted;
    ApiFixture fixture(corpus.value);
    fixture.activation_gate = std::make_shared<Gate>();
    auto state = open_installed_state(setup,
        Transport("https://example.test", fixture.handler()), open_installed_storage(setup, path));
    std::atomic_bool cancelled{false};
    std::atomic_int activation_result{-1};
    std::atomic_int import_result{-1};
    std::thread activation;
    std::thread importing;
    try {
        const auto request = state->offline_request();
        const auto file = offline_file(app_key, request.installation_id, 1,
            "offline_activation_logout_race", issued, issued + 120);
        require(state->import_offline_file(file, cancelled).access == Access::offline,
                "activation-race offline setup failed");
        activation = std::thread([&] {
            try { (void)state->activate("race-key", {}, std::nullopt, cancelled); }
            catch (const Error& error) { activation_result = static_cast<int>(error.kind()); }
            catch (...) { activation_result = static_cast<int>(ErrorKind::internal); }
        });
        fixture.activation_gate->wait_until_entered();
        importing = std::thread([&] {
            try { (void)state->import_offline_file(file, cancelled); import_result = 0; }
            catch (const Error& error) { import_result = static_cast<int>(error.kind()); }
            catch (...) { import_result = static_cast<int>(ErrorKind::internal); }
        });
        const bool import_waiting = wait_for_condition([&] {
            std::lock_guard<std::mutex> lock(state->lifecycle_mutex);
            return state->active_calls == 2;
        });
        require(import_waiting, "offline import did not queue behind the network activation");
        state->local_logout();
        fixture.activation_gate->release();
        activation.join();
        importing.join();
        require(activation_result == static_cast<int>(ErrorKind::stale_response) &&
                    import_result == static_cast<int>(ErrorKind::stale_response) &&
                    state->snapshot().access == Access::denied,
                "concurrent logout must fence both the activation response and queued import");
        state->close();
        state.reset();
        auto stored = open_installed_storage(setup, path);
        const auto bytes = stored->load();
        require(bytes.has_value(), "activation-race storage record disappeared");
        const auto record = persistent_codec::decode(setup, stored->provider(), *bytes);
        require(record["offline"]["jws"].isNull() && record["offline"]["sequence"] == 1 &&
                    record["credential"].isNull() && record["access"].isNull(),
                "concurrent logout must durably retain floors without authority resurrection");
    } catch (...) {
        fixture.activation_gate->release();
        if (activation.joinable()) activation.join();
        if (importing.joinable()) importing.join();
        if (state) state->close();
        state.reset();
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
        throw;
    }
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
}

void test_installed_identity_mismatch_rotates_installation(const Corpus& corpus) {
    const auto path = persistent_test_path();
    std::string old_id;
    {
        ApiFixture original(corpus.value);
        original.offline_activation = true;
        auto client = persistent_client_for(original, path);
        (void)client.activate("identity-bound-key");
        old_id = client.installation_id();
        client.close();
    }
    const Fingerprint custom{std::string(64, 'a'), "custom:fixture"};
    std::string custom_id;
    {
        ApiFixture changed(corpus.value);
        auto client = persistent_client_for(changed, path, custom);
        custom_id = client.installation_id();
        client.close();
        require(custom_id != old_id && changed.validate_calls == 0,
                "changed fingerprint must rotate installation without validating old authority");
    }
    {
        auto setup = config();
        setup.installation_id.reset();
        setup.fingerprint = custom;
        auto installed = open_installed_storage(setup, path);
        const auto bytes = installed->load();
        require(bytes.has_value(), "identity rotation must persist an installed record");
        const auto record = persistent_codec::decode(setup, installed->provider(), *bytes);
        require(record["installation"]["id"] == custom_id &&
                    record["installation"]["fingerprint"] == custom.value &&
                    record["installation"]["fingerprint_provider"] == custom.provider &&
                    record["credential"].isNull() && record["pending_activation"].isNull() &&
                    record["access"].isNull(),
                "changed fingerprint must persist no credential, pending mutation, or signed grant");
    }
    {
        ApiFixture unavailable(corpus.value);
        auto client = persistent_client_for(unavailable, path);
        const auto new_id = client.installation_id();
        client.close();
        require(new_id != custom_id && unavailable.validate_calls == 0,
                "unavailable fingerprint transition must rotate without validating old authority");
    }
    {
        auto setup = config();
        setup.installation_id.reset();
        auto installed = open_installed_storage(setup, path);
        const auto bytes = installed->load();
        require(bytes.has_value(), "unavailable identity transition must persist a new record");
        const auto record = persistent_codec::decode(setup, installed->provider(), *bytes);
        require(record["installation"]["fingerprint"].isNull() &&
                    record["installation"]["fingerprint_provider"].isNull() &&
                    record["credential"].isNull() && record["pending_activation"].isNull() &&
                    record["access"].isNull(),
                "unavailable fingerprint transition must clear saved identity and authority");
    }
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
}

void test_activation_accounts_and_proofs(const Corpus& corpus) {
    ApiFixture fixture(corpus.value);
    auto client = client_for(fixture);
    auto sibling = client;
    const auto activated = client.activate("key-from-stdin", "idempotency-123456");
    require(activated.access == Access::online, "activation should produce online access");
    require(activated.has_feature("export"), "verified export entitlement missing");
    const auto safe_snapshot = client.snapshot();
    require(safe_snapshot.access == Access::online && safe_snapshot.has_feature("export"),
            "typed snapshot must expose only access metadata");
    require(fixture.storage->load().second.has_value(), "verified credential was not stored");
    const auto reads_before_guard = fixture.storage->version_reads;
    require(client.require_access("export").access == Access::online,
            "require_access should accept a current entitlement");
    require(fixture.storage->version_reads > reads_before_guard,
            "warm access guard must retain its storage-generation invalidation read");
    Cancellation pre_cancelled;
    pre_cancelled.cancel();
    expect_error([&] { (void)client.require_access("export", &pre_cancelled); }, ErrorKind::cancelled);
    require(sibling.snapshot().access == Access::online,
            "client copies should share current access state");

    static_assert(!std::is_copy_constructible<PendingRegistration>::value, "pending registrations must remain move-only");
    auto registration = client.register_customer("license-key", "alice", "alice@example.test", "correct horse battery");
    require(registration.accepted && registration.expires_at.time_since_epoch().count() > 0 && registration.pending,
            "registration metadata/proof missing");
    client.resend_registration(registration.pending);
    auto other_client = client_for(fixture);
    expect_error([&] { other_client.resend_registration(registration.pending); }, ErrorKind::configuration);

    const auto logged_in = client.login("alice", "password");
    require(logged_in.customer.username == "alice", "login metadata mismatch");
    require(logged_in.customer.created_at.time_since_epoch().count() == 1767225600 &&
                logged_in.expires_at.time_since_epoch().count() == 1798761600,
            "ordinary account timestamps must preserve exact Unix seconds");
    require(client.customer_session_authorization() == "Bearer " + std::string(43, 's'),
            "customer proof mismatch");
    const auto safe_account = client.account();
    require(safe_account && safe_account->customer.username == "alice",
            "account metadata mismatch");
    const auto page = client.owned_licences("cursor_1");
    require(page.items.size() == 1 && page.next_cursor == std::optional<std::string>("cursor_2"),
            "owned licence metadata mismatch");
    require(page.items[0].duration == std::optional<std::chrono::seconds>(std::chrono::seconds(3000000000LL)),
            "owned licence duration must preserve values above i32 range");
    require(page.items[0].offline_file_duration == std::chrono::seconds(86400),
            "owned licence offline-file policy must parse exact server seconds");
    require(page.items[0].first_used_at && page.items[0].expires_at &&
                page.items[0].first_used_at->time_since_epoch().count() == 1767225600 &&
                page.items[0].expires_at->time_since_epoch().count() == 1798761600,
            "ordinary owned-licence timestamps must preserve exact Unix seconds");
    const auto claimed = client.claim_licence("claim-key", "claim-idempotency-123");
    require(claimed.id == "licence_1", "claim licence result mismatch");
    client.request_email_change("password", "new@example.test");
    client.request_password_recovery("alice@example.test");
    client.logout_account();
    require(!client.account(), "account logout did not clear local session");
    require(sibling.snapshot().access == Access::denied,
            "client copies should observe logout state");
}

void test_owned_licence_offline_file_policy_bounds(const Corpus& corpus) {
    ApiFixture fixture(corpus.value);
    auto client = client_for(fixture);
    (void)client.login("alice", "password");
    for (const std::int64_t seconds : {0, 86400, 31622400}) {
        fixture.offline_file_seconds = seconds;
        const auto page = client.owned_licences();
        require(page.items.size() == 1 && page.items.front().offline_file_duration ==
                std::chrono::seconds(seconds), "valid offline_file_seconds was not parsed exactly");
    }
    for (const std::int64_t seconds : {-1, 1, 86399, 31622401}) {
        fixture.offline_file_seconds = seconds;
        expect_error([&] { (void)client.owned_licences(); }, ErrorKind::invalid_response);
        (void)client.login("alice", "password");
    }
    fixture.omit_offline_file_seconds = true;
    expect_error([&] { (void)client.owned_licences(); }, ErrorKind::invalid_response);
    fixture.omit_offline_file_seconds = false;
    fixture.offline_file_seconds = 0;
    for (const int field : {1, 2}) {
        fixture.omit_limit_map = field;
        (void)client.login("alice", "password");
        expect_error([&] { (void)client.owned_licences(); }, ErrorKind::invalid_response);
    }
}

void test_public_timestamp_seconds_range() {
    ApiFixture fixture{Json::Value(Json::objectValue)};
    fixture.far_future_metadata = true;
    auto client = client_for(fixture);
    const auto account = client.login("alice", "password");
    require(account.customer.created_at.time_since_epoch().count() == 253370764800LL &&
                account.expires_at.time_since_epoch().count() == 253370764800LL,
            "year-9999 account timestamps must preserve seconds without clock-duration overflow");
    const auto page = client.owned_licences();
    require(page.items.size() == 1 && page.items[0].first_used_at && page.items[0].expires_at &&
                page.items[0].first_used_at->time_since_epoch().count() == 253402300799LL &&
                page.items[0].expires_at->time_since_epoch().count() == 253402300799LL,
            "year-9999 owned-licence timestamps must preserve exact Unix seconds");
}

void test_empty_explicit_activation_operation_ids(const Corpus& corpus) {
    ApiFixture fixture(corpus.value);
    auto client = client_for(fixture);
    (void)client.activate("initial-key");
    const std::optional<std::string_view> empty_id = std::string_view{};
    const auto request_count = [&] {
        std::lock_guard<std::mutex> lock(fixture.mutex);
        return fixture.requests.size();
    };
    auto requests_before = request_count();
    auto activation_calls_before = fixture.activation_calls.load();
    const auto key_access_before = client.snapshot().access;
    expect_error([&] { (void)client.activate("bad-id-key", empty_id); }, ErrorKind::configuration);
    expect_error([&] { (void)client.activate_previous("bad-id-key", "previous-credential", empty_id); },
                 ErrorKind::configuration);
    require(request_count() == requests_before && fixture.activation_calls == activation_calls_before &&
                client.snapshot().access == key_access_before,
            "empty explicit key operation IDs must fail before request or activation mutation");

    (void)client.login("alice", "password");
    requests_before = request_count();
    activation_calls_before = fixture.activation_calls.load();
    const auto account_access_before = client.snapshot().access;
    expect_error([&] { (void)client.activate_account("licence_1", empty_id); }, ErrorKind::configuration);
    expect_error([&] {
        (void)client.activate_account_previous("licence_1", "previous-credential", empty_id);
    }, ErrorKind::configuration);
    require(request_count() == requests_before && fixture.activation_calls == activation_calls_before &&
                client.snapshot().access == account_access_before,
            "empty explicit account operation IDs must fail before request or activation mutation");
}

void test_ensure_access_prompt_semantics(const Corpus& corpus) {
    ApiFixture fixture(corpus.value);
    auto client = client_for(fixture);
    int prompts = 0;
    expect_error([&] {
        (void)client.ensure_access("export", [&]() -> std::optional<std::string> {
            ++prompts;
            return std::nullopt;
        });
    }, ErrorKind::not_activated);
    require(prompts == 1, "ensure_access must ask once when access is not activated");
    const auto activated = client.ensure_access("export", [&]() -> std::optional<std::string> {
        ++prompts;
        return "key-from-prompt";
    });
    require(activated.access == Access::online && prompts == 2,
            "ensure_access must activate a supplied key and return typed access");
    require(client.ensure_access("export", [&]() -> std::optional<std::string> {
        ++prompts;
        return "unused";
    }).access == Access::online && prompts == 2,
        "ensure_access must not prompt when access already exists");
    expect_error([&] {
        (void)client.ensure_access("missing", [&]() -> std::optional<std::string> {
            ++prompts;
            return "unused";
        });
    }, ErrorKind::feature_unavailable);
    require(prompts == 2, "feature-unavailable must propagate without prompting");
}

void test_transport_retry_errors_and_cancellation() {
    std::atomic_bool cancelled{false};
    const std::string path = "/api/client/v1/test";
    std::atomic_int safe_attempts{0};
    Transport safe("https://example.test", [&](auto, auto, auto, auto, const auto&) {
        const auto attempt = ++safe_attempts;
        return attempt < 3 ? HttpResponse{502, "{}", "0"}
                           : HttpResponse{200, R"({"ok":true})", {}};
    });
    require(safe.get(path, cancelled)->operator[]("ok").asBool() && safe_attempts == 3,
            "safe requests must retry at most twice before succeeding");

    std::atomic_int unsafe_attempts{0};
    Transport unsafe("https://example.test", [&](auto, auto, auto, auto, const auto&) {
        ++unsafe_attempts;
        return HttpResponse{503, "{}", {}};
    });
    expect_error([&] { (void)unsafe.post(path, Json::Value(Json::objectValue), false, cancelled); },
                 ErrorKind::transient);
    require(unsafe_attempts == 1, "unsafe posts must never retry");

    std::atomic_int temporary_attempts{0};
    Transport temporary("https://example.test", [&](auto, auto, auto, auto, const auto&) {
        ++temporary_attempts;
        return HttpResponse{503,
            R"({"error":{"code":"service_unavailable","message":"try later","request_id":"request_42"}})", "0"};
    });
    const auto temporary_error = expect_error([&] {
        (void)temporary.get(path, cancelled);
    }, ErrorKind::transient);
    require(temporary_attempts == 3 && temporary_error.request_id() == "request_42",
            "explicit transient envelopes must retry and retain safe request IDs");

    std::atomic_int denied_attempts{0};
    Transport denied("https://example.test", [&](auto, auto, auto, auto, const auto&) {
        ++denied_attempts;
        return HttpResponse{403,
            R"({"error":{"code":"feature_disabled","message":"No access","request_id":"deny_1"}})", {}};
    });
    const auto denied_error = expect_error([&] { (void)denied.get(path, cancelled); }, ErrorKind::denied);
    require(denied_attempts == 1 && denied_error.code() == "feature_disabled" &&
            denied_error.request_id() == "deny_1", "explicit denial must not be treated as an outage");

    std::atomic_int redirect_attempts{0};
    Transport redirect("https://example.test", [&](auto, auto, auto, auto, const auto&) {
        ++redirect_attempts;
        return HttpResponse{302, R"({"moved":true})", {}};
    });
    expect_error([&] { (void)redirect.get(path, cancelled); }, ErrorKind::invalid_response);
    require(redirect_attempts == 1, "redirect responses must not be followed or retried");

    std::mutex mutex;
    std::condition_variable condition;
    bool entered = false;
    Transport waiting("https://example.test", [&](auto, auto, auto, auto, const auto& cancel) {
        std::unique_lock<std::mutex> lock(mutex);
        entered = true;
        condition.notify_all();
        while (!cancel.load()) condition.wait_for(lock, std::chrono::milliseconds(5));
        return HttpResponse{200, R"({"ok":true})", {}};
    });
    ErrorKind result = ErrorKind::none;
    std::thread worker([&] {
        try { (void)waiting.get(path, cancelled); }
        catch (const Error& error) { result = error.kind(); }
    });
    {
        std::unique_lock<std::mutex> lock(mutex);
        condition.wait(lock, [&] { return entered; });
    }
    cancelled.store(true);
    worker.join();
    require(result == ErrorKind::cancelled, "cancellation must win over a late successful response");

    for (const auto invalid_origin : {"http://example.test", "https://example.test/path",
                                      "https://user@example.test", "https://example.test/?q=x"}) {
        expect_error([&] { (void)Transport(invalid_origin); }, ErrorKind::configuration);
    }
}

void test_logout_generation_fences_late_responses(const Corpus& corpus) {
    {
        ApiFixture fixture(corpus.value);
        fixture.activation_gate = std::make_shared<Gate>();
        auto client = client_for(fixture);
        std::atomic_int result{-1};
        std::thread worker([&] {
            try { (void)client.activate("key-from-stdin", "idempotency-123456"); }
            catch (const Error& error) { result.store(static_cast<int>(error.kind())); }
        });
        fixture.activation_gate->wait_until_entered();
        client.logout();
        fixture.activation_gate->release();
        worker.join();
        require(result == static_cast<int>(ErrorKind::stale_response) && !fixture.storage->load().second,
                "local logout must fence late activation results before storage writes");
    }
    {
        ApiFixture fixture(corpus.value);
        fixture.sessions_gate = std::make_shared<Gate>();
        auto client = client_for(fixture);
        std::atomic_int result{-1};
        std::thread worker([&] {
            try { (void)client.login("alice", "password"); }
            catch (const Error& error) { result.store(static_cast<int>(error.kind())); }
        });
        fixture.sessions_gate->wait_until_entered();
        client.logout();
        fixture.sessions_gate->release();
        worker.join();
        require(result == static_cast<int>(ErrorKind::stale_response) && !client.account(),
                "local logout must fence late login results");
    }
    for (const bool fail_logout : {false, true}) {
        ApiFixture fixture(corpus.value);
        auto client = client_for(fixture);
        (void)client.login("alice", "password");
        fixture.logout_gate = std::make_shared<Gate>();
        fixture.logout_error = fail_logout;
        std::atomic_int result{-1};
        std::thread worker([&] {
            try { client.logout_account(); }
            catch (const Error& error) { result.store(static_cast<int>(error.kind())); }
        });
        fixture.logout_gate->wait_until_entered();
        require(!client.account(), "account logout must clear local metadata before network completion");
        expect_error([&] { (void)client.customer_session_authorization(); }, ErrorKind::reauthentication_required);
        (void)client.login("alice", "password");
        require(client.account() && client.account()->customer.username == "alice",
                "new account login must be visible while old logout is pending");
        fixture.logout_gate->release();
        worker.join();
        require(result == static_cast<int>(ErrorKind::stale_response) &&
                client.account() && client.account()->customer.username == "alice",
                "late logout success or error must not affect a newer account session");
    }
    for (const bool fail_deactivation : {false, true}) {
        ApiFixture fixture(corpus.value);
        auto client = client_for(fixture);
        (void)client.activate("key-from-stdin", "idempotency-123456");
        fixture.deactivation_gate = std::make_shared<Gate>();
        fixture.deactivation_error = fail_deactivation;
        std::atomic_int result{-1};
        std::thread worker([&] {
            try { client.deactivate("deactivate-idempotency-123"); }
            catch (const Error& error) { result.store(static_cast<int>(error.kind())); }
        });
        fixture.deactivation_gate->wait_until_entered();
        const auto newer = client.activate("key-from-stdin", "new-activation-idempotency");
        require(newer.access == Access::online, "new activation must complete while deactivation is pending");
        fixture.deactivation_gate->release();
        worker.join();
        require(result == static_cast<int>(ErrorKind::stale_response) &&
                fixture.storage->load().second.has_value() &&
                client.snapshot().access == Access::online,
                "late deactivation success or error must not clear a newer activation");
    }
}

void test_unauthenticated_generation_fences(const Corpus& corpus) {
    {
        ApiFixture fixture(corpus.value);
        fixture.registration_gate = std::make_shared<Gate>();
        auto client = client_for(fixture);
        std::atomic_int result{-1};
        std::thread worker([&] {
            try {
                (void)client.register_customer("license-key", "alice", "alice@example.test",
                                               "correct horse battery");
            } catch (const Error& error) {
                result.store(static_cast<int>(error.kind()));
            }
        });
        fixture.registration_gate->wait_until_entered();
        const auto newer = client.activate("key-from-stdin", "new-activation-idempotency");
        require(newer.access == Access::online, "activation must complete while registration is pending");
        fixture.registration_gate->release();
        worker.join();
        require(result == static_cast<int>(ErrorKind::stale_response) &&
                fixture.storage->load().second.has_value() &&
                client.snapshot().access == Access::online,
                "late registration proof must not outlive a newer activation");
    }
    {
        ApiFixture fixture(corpus.value);
        auto client = client_for(fixture);
        auto registration = client.register_customer("license-key", "alice", "alice@example.test",
                                                    "correct horse battery");
        fixture.resend_gate = std::make_shared<Gate>();
        std::atomic_int result{-1};
        std::thread worker([&] {
            try { client.resend_registration(registration.pending); }
            catch (const Error& error) { result.store(static_cast<int>(error.kind())); }
        });
        fixture.resend_gate->wait_until_entered();
        client.logout();
        fixture.resend_gate->release();
        worker.join();
        require(result == static_cast<int>(ErrorKind::stale_response),
                "late registration resend proof must be fenced by logout");
    }
    {
        ApiFixture fixture(corpus.value);
        fixture.recovery_gate = std::make_shared<Gate>();
        auto client = client_for(fixture);
        std::atomic_int result{-1};
        std::thread worker([&] {
            try { client.request_password_recovery("alice@example.test"); }
            catch (const Error& error) { result.store(static_cast<int>(error.kind())); }
        });
        fixture.recovery_gate->wait_until_entered();
        client.logout();
        fixture.recovery_gate->release();
        worker.join();
        require(result == static_cast<int>(ErrorKind::stale_response),
                "late password recovery proof must be fenced by logout");
    }
}

template <class Predicate>
bool wait_for_condition(Predicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!predicate()) {
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return true;
}

void test_persistent_close_cancels_foreground(const Corpus& corpus) {
    FakeClock clock;
    for (const bool activation : {false, true}) {
        const auto path = persistent_test_path();
        auto setup = config();
        setup.installation_id.reset();
        ApiFixture fixture(corpus.value);
        fixture.offline_activation = true;
        auto delegate = fixture.handler();
        std::atomic_bool block{false}, entered{false}, observed_cancel{false};
        auto state = open_installed_state(setup, Transport("https://example.test",
            [&](auto method, auto url, auto bearer_value, auto body, const auto& cancelled) {
                if (block.load() && url.find("/activations") != std::string_view::npos) {
                    entered = true;
                    observed_cancel = wait_for_condition([&] { return cancelled.load(); });
                }
                // Deliberately return a successful response after observing close.
                return delegate(method, url, bearer_value, body, cancelled);
            }), open_installed_storage(setup, path));
        std::atomic_bool inactive{false};
        if (!activation) (void)state->activate("close-key", {}, std::nullopt, inactive);
        block = true;
        std::atomic_int first{-1}, queued{-1};
        std::thread request([&] {
            try {
                if (activation) (void)state->activate("close-key", {}, std::nullopt, inactive);
                else (void)state->refresh(inactive);
            } catch (const Error& error) { first = static_cast<int>(error.kind()); }
        });
        const bool request_entered = wait_for_condition([&] { return entered.load(); });
        std::thread waiting([&] {
            try { (void)state->refresh(inactive); }
            catch (const Error& error) { queued = static_cast<int>(error.kind()); }
        });
        const bool both_active = wait_for_condition([&] {
            std::lock_guard<std::mutex> lock(state->lifecycle_mutex);
            return state->active_calls == 2;
        });
        const auto started = std::chrono::steady_clock::now();
        state->close();
        request.join();
        waiting.join();
        require(request_entered && both_active && observed_cancel &&
                    std::chrono::steady_clock::now() - started < std::chrono::seconds(1),
                "installed close must cancel foreground transport and serial waits promptly");
        require(first == static_cast<int>(ErrorKind::cancelled) &&
                    queued == static_cast<int>(ErrorKind::cancelled),
                "close must reject both late success and queued foreground work");
        auto storage = open_installed_storage(setup, path);
        const auto record = persistent_codec::decode(setup, storage->provider(), *storage->load());
        require(activation ? (record["credential"].isNull() && !record["pending_activation"].isNull())
                           : (!record["credential"].isNull() && !record["access"].isNull()),
                "close must preserve saved activation or unresolved replay identity without late acceptance");
        storage.reset();
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
}

void test_owner_cancellation_during_backoff() {
    auto owner = std::make_shared<std::atomic_bool>(false);
    std::atomic_bool inactive{false};
    std::atomic_int requests{0}, result{-1};
    Transport transport("https://example.test", [&](auto, auto, auto, auto, const auto&) {
        ++requests;
        return HttpResponse{503, "{}", "10"};
    });
    transport.bind_owner_cancellation(owner);
    std::thread request([&] {
        try { (void)transport.get("/api/client/v1/status", inactive); }
        catch (const Error& error) { result = static_cast<int>(error.kind()); }
    });
    const bool started = wait_for_condition([&] { return requests.load() != 0; });
    const auto cancelled_at = std::chrono::steady_clock::now();
    owner->store(true);
    request.join();
    require(started && requests == 1 && result == static_cast<int>(ErrorKind::cancelled) &&
                std::chrono::steady_clock::now() - cancelled_at < std::chrono::seconds(1),
            "owner cancellation must interrupt transport retry backoff");
}

class FailingInstalledStorage final : public InstalledStorage {
public:
    explicit FailingInstalledStorage(std::shared_ptr<InstalledStorage> wrapped)
        : wrapped_(std::move(wrapped)) {}
    bool initialization_needed() const noexcept override { return wrapped_->initialization_needed(); }
    void verify() override { wrapped_->verify(); }
    std::optional<std::string> load() override { return wrapped_->load(); }
    void initialize(std::string_view bytes) override { wrapped_->initialize(bytes); }
    void save(std::string_view bytes) override {
        const auto attempt = ++save_attempts;
        if (fail.load()) {
            ++failed_writes;
            throw Error(1, ErrorKind::storage, "installation_state_write_failed", {});
        }
        wrapped_->save(bytes);
        if (after_successful_save) after_successful_save(attempt);
    }
    std::string_view provider() const noexcept override { return wrapped_->provider(); }
    std::atomic_bool fail{false};
    std::atomic_int failed_writes{0};
    std::atomic_int save_attempts{0};
    std::function<void(int)> after_successful_save;
private:
    std::shared_ptr<InstalledStorage> wrapped_;
};

void test_offline_worker_preserves_clock_uncertainty(const Corpus& corpus) {
    FakeClock clock;
    constexpr std::int64_t issued = 1700000000;
    clock.wall = issued;
    std::ifstream offline_input(ORBIT_OFFLINE_VECTORS_PATH, std::ios::binary);
    require(offline_input.good(), "offline test vector file is unavailable");
    const auto offline_corpus = parse_json(
        std::string((std::istreambuf_iterator<char>(offline_input)), {}), 2 * 1024 * 1024);
    const auto trusted = std::make_shared<const orbit::detail::OfflineKeys>(
        orbit::detail::OfflineKeys::parse(offline_corpus["jwks"], "test"));
    const auto app_key = AppKey::parse(
        "orbit_app_test_" + base64url_encode(
            reinterpret_cast<const unsigned char*>("https://orbit.example.test"),
            std::string_view("https://orbit.example.test").size()) + ".app.test");
    const auto path = persistent_test_path();
    auto setup = config();
    setup.installation_id.reset();
    setup.public_app_key = app_key.public_key();
    setup.offline_keys = trusted;
    ApiFixture fixture(corpus.value);
    auto state = open_installed_state(setup,
        Transport("https://example.test", fixture.handler()), open_installed_storage(setup, path));
    auto public_client = make_test_client_from_state(state);
    const auto no_requests = [&] {
        std::lock_guard<std::mutex> lock(fixture.mutex);
        return fixture.requests.empty();
    };
    try {
        const auto request = state->offline_request();
        const auto file = offline_file(app_key, request.installation_id, 1,
            "offline_worker_clock_error", issued, issued + 300);
        std::atomic_bool cancelled{false};
        require(state->import_offline_file(file, cancelled).access == Access::offline,
                "worker clock regression file import failed");
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            const auto expired_checkpoint = std::chrono::steady_clock::now() - std::chrono::seconds(61);
            state->offline->last_checkpoint = expired_checkpoint;
            state->offline_clock->last_checkpoint = expired_checkpoint;
        }
        clock.elapsed.fetch_add(61000000000LL); // Deliberately hold wall time fixed.
        state->wake_worker();
        const bool rejected_checkpoint = wait_for_condition([&] {
            std::lock_guard<std::mutex> lock(state->mutex);
            return state->worker_cancelled.load() && state->offline && state->offline->uncertain &&
                state->offline_clock && state->offline_clock->uncertain;
        });
        require(rejected_checkpoint,
                "worker clock-checkpoint failure must retain uncertain active file mode and its time floor");
        int prompts = 0;
        const auto access_error = expect_error([&] {
            (void)public_client.ensure_access("export", [&]() -> std::optional<std::string> {
                ++prompts;
                return "unexpected-key";
            });
        }, ErrorKind::clock_uncertain);
        require(access_error.code() == "clock_uncertain" && prompts == 0 && no_requests(),
                "uncertain file mode must fail closed without becoming activation-required or sending HTTP");
        clock.wall.fetch_add(61);
        const auto renewed = offline_file(app_key, request.installation_id, 2,
            "offline_worker_clock_recovered", issued + 61, issued + 240);
        require(state->import_offline_file(renewed, cancelled).access == Access::offline,
                "a corrected clock must permit deliberate signed renewal after a worker error");
        require(no_requests(), "offline worker failure or renewal must not send HTTP");
        public_client.close();
        state->close();
        state.reset();
    } catch (...) {
        state->close();
        state.reset();
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
        throw;
    }
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
}

void test_offline_durable_import_fences(const Corpus& corpus) {
    for (const std::string scenario : {"cancel_save", "cancel_checkpoint", "expire_write"}) {
        FakeClock clock;
        constexpr std::int64_t issued = 1700000000;
        clock.wall = issued;
        std::ifstream offline_input(ORBIT_OFFLINE_VECTORS_PATH, std::ios::binary);
        require(offline_input.good(), "offline test vector file is unavailable");
        const auto offline_corpus = parse_json(
            std::string((std::istreambuf_iterator<char>(offline_input)), {}), 2 * 1024 * 1024);
        const auto trusted = std::make_shared<const orbit::detail::OfflineKeys>(
            orbit::detail::OfflineKeys::parse(offline_corpus["jwks"], "test"));
        const auto app_key = AppKey::parse(
            "orbit_app_test_" + base64url_encode(
                reinterpret_cast<const unsigned char*>("https://orbit.example.test"),
                std::string_view("https://orbit.example.test").size()) + ".app.test");
        const auto path = persistent_test_path();
        auto setup = config();
        setup.installation_id.reset();
        setup.public_app_key = app_key.public_key();
        setup.offline_keys = trusted;
        ApiFixture fixture(corpus.value);
        auto storage = std::make_shared<FailingInstalledStorage>(open_installed_storage(setup, path));
        auto state = open_installed_state(setup,
            Transport("https://example.test", fixture.handler()), storage);
        try {
            const auto request = state->offline_request();
            const auto file = offline_file(app_key, request.installation_id, 1,
                "offline_durable_" + scenario, issued, issued + 120);
            std::atomic_bool cancelled{false};
            storage->after_successful_save = [&](int attempt) {
                if (scenario == "cancel_save" && attempt == 1) cancelled = true;
                if (scenario == "cancel_checkpoint" && attempt == 1) {
                    clock.elapsed.fetch_add(1000000000LL);
                    clock.wall.fetch_add(1);
                }
                if (scenario == "cancel_checkpoint" && attempt == 2) cancelled = true;
                if (scenario == "expire_write" && attempt == 1) {
                    clock.elapsed.fetch_add(121000000000LL);
                    clock.wall.fetch_add(121);
                }
            };
            expect_error([&] { (void)state->import_offline_file(file, cancelled); },
                scenario == "expire_write" ? ErrorKind::denied : ErrorKind::cancelled);
            storage->after_successful_save = {};
            const auto bytes = storage->load();
            require(bytes.has_value(), "durable import fence lost its record");
            const auto record = persistent_codec::decode(setup, storage->provider(), *bytes);
            require(record["offline"]["jws"].isNull() && record["offline"]["sequence"] == 1 &&
                        record["credential"].isNull() && record["access"].isNull(),
                    "post-write cancellation or expiry must durably clear the signed file and retain its floor");
            storage->after_successful_save = {};
            state->close();
            state.reset();
            storage.reset();
            auto reopened = open_installed_state(setup,
                Transport("https://example.test", fixture.handler()), open_installed_storage(setup, path));
            require(reopened->snapshot().access == Access::denied,
                    "a cleared durable import must not restore after reopening");
            reopened->close();
        } catch (...) {
            if (storage) storage->after_successful_save = {};
            if (state) state->close();
            state.reset();
            std::error_code ignored;
            std::filesystem::remove_all(path, ignored);
            throw;
        }
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
}

void test_persistent_worker_stops_on_storage_failure(const Corpus& corpus) {
    FakeClock clock;
    const auto path = persistent_test_path();
    auto setup = config();
    setup.installation_id.reset();
    ApiFixture fixture(corpus.value);
    fixture.offline_activation = true;
    auto storage = std::make_shared<FailingInstalledStorage>(open_installed_storage(setup, path));
    auto state = open_installed_state(setup, Transport("https://example.test", fixture.handler()), storage);
    std::atomic_bool inactive{false};
    (void)state->activate("disk-failure-key", {}, std::nullopt, inactive);
    storage->fail = true;
    clock.advance(900);
    state->wake_worker();
    const bool failed = wait_for_condition([&] { return state->persistence_failed.load(); });
    bool authority_cleared = false;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        authority_cleared = !state->claims && !state->anchor;
    }
    state->close();
    require(failed && authority_cleared && state->worker_cancelled.load() &&
                fixture.validate_calls == 1 && storage->failed_writes == 1,
            "one failed refresh persistence must clear runtime authority and stop worker retries");
    storage.reset();
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
}

#if defined(__linux__)
void test_installed_lease_replacement_fails_closed(const Corpus& corpus) {
    FakeClock clock;
    const auto path = persistent_test_path();
    auto setup = config();
    setup.installation_id.reset();
    ApiFixture fixture(corpus.value);
    auto installed = std::make_shared<FailingInstalledStorage>(open_installed_storage(setup, path));
    auto state = open_installed_state(setup,
        Transport("https://example.test", fixture.handler()), installed);
    std::atomic_bool cancelled{false};
    require(state->activate("lease-replacement-key", {}, std::nullopt, cancelled).access == Access::online,
            "installed lease test activation failed");
    installed->save_attempts = 0;
    const auto request_count = [&] {
        std::lock_guard<std::mutex> lock(fixture.mutex);
        return fixture.requests.size();
    };
    const auto requests_before = request_count();
    const auto record_path = std::filesystem::path(path) / "orbit-installed.state";
    const auto lease_path = std::filesystem::path(path) / "orbit-storage.lock";
    const auto moved_lease_path = std::filesystem::path(path) / "orbit-storage.lock.saved";
    const auto read_record = [&] {
        std::ifstream input(record_path, std::ios::binary);
        require(input.good(), "installed lease test record cannot be opened");
        return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    };
    const auto record_before = read_record();
    std::error_code rename_error;
    std::filesystem::rename(lease_path, moved_lease_path, rename_error);
    require(!rename_error, "installed lease test could not rename the active lease");
    const int replacement = ::open(lease_path.c_str(), O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    require(replacement >= 0, "installed lease test could not create a replacement lease");
    (void)::close(replacement);

    reset_access_benchmark_metrics();
    expect_error([&] { (void)state->snapshot(); }, ErrorKind::storage);
    expect_error([&] { (void)state->require_access("export", cancelled); }, ErrorKind::storage);
    require(state->persistence_failed.load() && !state->credential && !state->claims && !state->anchor,
            "lease verification failure must poison storage and clear volatile authority");
    require(request_count() == requests_before && read_record() == record_before &&
                access_benchmark_storage_writes() == 0 && installed->save_attempts == 0,
            "invalid installed lease must block access without HTTP or a state-file rewrite");
    state->close();
    require(installed->save_attempts == 0,
            "closing a poisoned installed client must not rewrite its untrusted state path");
    state.reset();
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
}
#endif

void test_persistent_invalid_cache_clock_recovers_credential(const Corpus& corpus) {
    FakeClock clock;
    for (const int mutation : {0, 1, 2}) {
        for (const bool outage : {false, true}) {
            const auto path = persistent_test_path();
            ApiFixture first(corpus.value);
            first.offline_activation = true;
            auto client = persistent_client_for(first, path);
            (void)client.activate("invalid-cache-clock-key");
            client.close();
            auto setup = config();
            setup.installation_id.reset();
            {
                auto storage = open_installed_storage(setup, path);
                auto record = persistent_codec::decode(setup, storage->provider(), *storage->load());
                auto& access = record["access"];
                if (mutation == 0) access["server_high_water"] = Json::Int64(json_int64(access["received_server_time"]) - 1);
                else if (mutation == 1) access["wall_high_water"] = Json::Int64(json_int64(access["received_wall_time"]) - 1);
                else access["server_high_water"] = Json::Int64(json_int64(access["server_high_water"]) + 40);
                storage->save(persistent_codec::encode(setup, storage->provider(), record));
            }
            ApiFixture recovery(corpus.value);
            recovery.persistent_mode = true;
            recovery.offline_activation = true;
            recovery.offline_refresh = outage;
            auto reopened = persistent_client_for(recovery, path);
            const auto snapshot = reopened.snapshot();
            require(snapshot.access == (outage ? Access::refresh_required : Access::online) &&
                        !snapshot.reauthentication_required &&
                        recovery.activation_calls == 0 && recovery.validate_calls == (outage ? 3 : 1),
                    "invalid cache clock must preserve the credential for online validation only");
            reopened.close();
            if (outage) {
                {
                    auto storage = open_installed_storage(setup, path);
                    const auto record = persistent_codec::decode(setup, storage->provider(), *storage->load());
                    require(record["access"].isNull() && !record["credential"].isNull(),
                            "invalid offline cache must be durably discarded without removing credential");
                }
                recovery.offline_refresh = false;
                auto online = persistent_client_for(recovery, path);
                require(online.snapshot().access == Access::online && recovery.activation_calls == 0,
                        "saved credential must recover after invalid clock cache and boot outage");
                online.close();
            }
            std::error_code ignored;
            std::filesystem::remove_all(path, ignored);
        }
    }
}

#if defined(_WIN32)
void test_windows_interrupted_installed_write(const Corpus& corpus) {
    FakeClock clock;
    using storage_windows::InstalledWriteFault;
    for (const auto stage : {InstalledWriteFault::fenced, InstalledWriteFault::temporary_written,
                             InstalledWriteFault::replaced}) {
        const auto path = persistent_test_path();
        ApiFixture fixture(corpus.value);
        fixture.offline_activation = true;
        auto client = persistent_client_for(fixture, path);
        (void)client.activate("interrupted-invalidation-key");
        client.close();
        auto setup = config();
        setup.installation_id.reset();
        {
            auto storage = open_installed_storage(setup, path);
            auto record = persistent_codec::decode(setup, storage->provider(), *storage->load());
            require(!record["access"].isNull(), "fault test needs prior signed authority");
            record["access"] = Json::nullValue;
            record["credential"] = Json::nullValue;
            storage_windows::set_installed_write_fault(stage);
            try {
                expect_error([&] { storage->save(persistent_codec::encode(setup, storage->provider(), record)); },
                             ErrorKind::storage);
            } catch (...) {
                storage_windows::set_installed_write_fault(InstalledWriteFault::none);
                throw;
            }
            storage_windows::set_installed_write_fault(InstalledWriteFault::none);
        }
        expect_error([&] { (void)open_installed_storage(setup, path); }, ErrorKind::storage);
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
}
#endif

void test_persistent_online_restart_and_offline_recovery(const Corpus& corpus) {
    FakeClock clock;
    const auto path = persistent_test_path();
    std::int64_t original_expiry = 0;
    std::string installation;
    {
        ApiFixture first(corpus.value);
        first.offline_activation = true;
        auto client = persistent_client_for(first, path);
        require(first.activation_calls == 0 && first.validate_calls == 0,
                "fresh installed open must not make a network request");
        installation = client.installation_id();
        const auto activated = client.activate("persistent-license-key");
        require(activated.access == Access::online && !activated.credential_expires_at,
                "persistent activation must explicitly negotiate a null credential expiry");
        require(first.persistent_mode.load() && first.activation_calls == 1,
                "key-first activation must request persistent credential mode");
        original_expiry = std::chrono::duration_cast<std::chrono::seconds>(
            activated.expires_at->time_since_epoch()).count();
        client.close();
    }
#if defined(__linux__)
    struct stat directory_info{};
    struct stat file_info{};
    const auto data_path = (std::filesystem::path(path) / "orbit-installed.state").string();
    require(::stat(path.c_str(), &directory_info) == 0 &&
                (directory_info.st_mode & 0777) == 0700,
            "installed state directory must be private");
    require(::stat(data_path.c_str(), &file_info) == 0 &&
                (file_info.st_mode & 0777) == 0600,
            "installed state file must be private");
#endif
    {
        std::ifstream input(std::filesystem::path(path) / "orbit-installed.state", std::ios::binary);
        const std::string bytes((std::istreambuf_iterator<char>(input)), {});
        require(bytes.find("persistent-license-key") == std::string::npos,
                "persistent state must not contain the raw licence key");
    }
    {
        ApiFixture online(corpus.value);
        online.persistent_mode = true;
        online.offline_activation = true;
        auto client = persistent_client_for(online, path);
        require(client.installation_id() == installation && online.validate_calls == 1 &&
                    online.activation_calls == 0,
                "restart must reuse the installation and validate without asking for a key");
        const auto state = client.snapshot();
        require(state.access == Access::online && state.expires_at &&
                    std::chrono::duration_cast<std::chrono::seconds>(state.expires_at->time_since_epoch()).count() == original_expiry,
                "online restart must retain the original signed grant deadline");
        client.close();
    }
    {
        ApiFixture offline(corpus.value);
        offline.persistent_mode = true;
        offline.offline_activation = true;
        offline.offline_refresh = true;
        auto client = persistent_client_for(offline, path);
        const auto state = client.snapshot();
        require(offline.validate_calls == 3 && state.access == Access::offline && state.expires_at &&
                    std::chrono::duration_cast<std::chrono::seconds>(state.expires_at->time_since_epoch()).count() == original_expiry,
                "transient validation may restore only the original offline-enabled grant");
        require(client.require_access("export").access == Access::offline,
                "offline restart must still enforce access through require_access");
        client.close();
    }
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
}

void test_persistent_uncertain_activation_reuses_identity(const Corpus& corpus) {
    FakeClock clock;
    const auto path = persistent_test_path();
    std::string first_operation;
    {
        ApiFixture malformed(corpus.value);
        malformed.malformed_activation = true;
        auto client = persistent_client_for(malformed, path);
        expect_error([&] { (void)client.activate("same-key-after-restart"); },
                     ErrorKind::invalid_response);
        {
            std::lock_guard<std::mutex> lock(malformed.mutex);
            first_operation = malformed.last_activation_idempotency;
        }
        require(first_operation.size() >= 16 && malformed.activation_calls == 1,
                "uncertain activation must save its operation identity before sending");
        expect_error([&] { (void)client.activate("different-key"); }, ErrorKind::configuration);
        require(malformed.activation_calls == 1,
                "changed activation input must not be sent while recovery is pending");
        client.close();
    }
    {
        ApiFixture recovered(corpus.value);
        recovered.persistent_mode = true;
        recovered.offline_activation = true;
        auto client = persistent_client_for(recovered, path);
        require(recovered.validate_calls == 0,
                "open with pending activation must leave its retry identity untouched");
        (void)client.activate("same-key-after-restart");
        {
            std::lock_guard<std::mutex> lock(recovered.mutex);
            require(recovered.last_activation_idempotency == first_operation,
                    "same uncertain key must reuse its operation ID after restart");
        }
        client.close();
    }
    auto setup = config();
    setup.installation_id.reset();
    {
        auto installed = open_installed_storage(setup, path);
        const auto bytes = installed->load();
        require(bytes.has_value(), "accepted retry must leave a durable installation record");
        const auto record = persistent_codec::decode(setup, installed->provider(), *bytes);
        require(record["pending_activation"].isNull(),
                "verified durable acceptance must clear the pending mutation");
    }
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
}

void test_persistent_account_activation_survives_failed_login(const Corpus& corpus) {
    FakeClock clock;
    const auto path = persistent_test_path();
    const std::string password = "never-persist-account-password";
    const std::string account_session(43, 's');
    auto read_record = [&] {
        auto setup = config();
        setup.installation_id.reset();
        auto installed = open_installed_storage(setup, path);
        const auto bytes = installed->load();
        require(bytes.has_value(), "account activation recovery record is missing");
        return persistent_codec::decode(setup, installed->provider(), *bytes);
    };
    std::string operation_id;
    {
        ApiFixture lost(corpus.value);
        auto client = persistent_client_for(lost, path);
        const auto account = client.login("alice", password);
        require(account.customer.id == "customer_1",
                "initial account login must identify the expected customer");
        lost.activation_response_lost = true;
        expect_error([&] { (void)client.activate_account("licence"); }, ErrorKind::transient);
        {
            std::lock_guard<std::mutex> lock(lost.mutex);
            operation_id = lost.last_activation_idempotency;
        }
        require(operation_id.size() >= 16 && lost.activation_calls > 0,
                "uncertain account activation must save its operation identity before sending");
        client.close();
    }
    const auto pending_record = read_record();
    require(pending_record["pending_activation"]["principal_kind"] == "account" &&
                pending_record["pending_activation"]["operation_id"] == operation_id &&
                pending_record["credential"].isNull() && pending_record["access"].isNull(),
            "uncertain account activation must persist only its retry identity");
    auto persisted = encode_json(pending_record);
    require(persisted.find(password) == std::string::npos &&
                persisted.find(account_session) == std::string::npos &&
                !pending_record.isMember("password") && !pending_record.isMember("customer_session"),
            "account password and session must not be persisted");

    {
        ApiFixture rejected(corpus.value);
        rejected.login_denied = true;
        auto client = persistent_client_for(rejected, path);
        expect_error([&] { (void)client.login("alice", "wrong-account-password"); }, ErrorKind::denied);
        client.close();
    }
    const auto after_failure = read_record();
    require(after_failure["pending_activation"]["operation_id"] == operation_id &&
                after_failure["credential"].isNull() && after_failure["access"].isNull(),
            "failed login must clear account/access authority while retaining pending activation identity");
    persisted = encode_json(after_failure);
    require(persisted.find(password) == std::string::npos &&
                persisted.find("wrong-account-password") == std::string::npos &&
                persisted.find(account_session) == std::string::npos,
            "failed login must not persist account credentials");

    {
        ApiFixture recovered(corpus.value);
        auto client = persistent_client_for(recovered, path);
        const auto account = client.login("alice", password);
        require(account.customer.id == "customer_1",
                "recovery login must verify the same customer identity");
        const auto accepted = client.activate_account("licence");
        require(accepted.access == Access::online,
                "account activation should recover after successful login");
        {
            std::lock_guard<std::mutex> lock(recovered.mutex);
            require(recovered.last_activation_idempotency == operation_id,
                    "account activation retry must reuse its original operation ID");
        }
        client.close();
    }
    const auto recovered_record = read_record();
    require(recovered_record["pending_activation"].isNull() &&
                !recovered_record["credential"].isNull(),
            "verified retry must clear pending identity and persist the activation credential");
    persisted = encode_json(recovered_record);
    require(persisted.find(password) == std::string::npos &&
                persisted.find(account_session) == std::string::npos,
            "successful account login session and password must remain memory-only");
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
}

void test_persistent_previous_rebind_and_expiry_contract(const Corpus& corpus) {
    FakeClock clock;
    const auto path = persistent_test_path();
    {
        ApiFixture fixture(corpus.value);
        fixture.offline_activation = true;
        auto client = persistent_client_for(fixture, path);
        const std::string supplied(43, 'p');
        (void)client.activate_previous("rebind-key", supplied,
                                        "explicit-rebind-operation-123");
        {
            std::lock_guard<std::mutex> lock(fixture.mutex);
            require(fixture.last_previous_credential == supplied,
                    "fresh persistent installation must send the caller's previous credential");
        }
        client.close();
    }
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);

    for (const bool omit_expiry : {true, false}) {
        const auto invalid_path = persistent_test_path();
        ApiFixture fixture(corpus.value);
        fixture.finite_persistent_response = !omit_expiry;
        fixture.missing_expiry = omit_expiry;
        auto client = persistent_client_for(fixture, invalid_path);
        expect_error([&] { (void)client.activate("persistent-mode-key"); },
                     ErrorKind::invalid_response);
        client.close();
        std::filesystem::remove_all(invalid_path, ignored);
    }
}

void test_persistent_strict_outage_is_not_activation_required(const Corpus& corpus) {
    FakeClock clock;
    const auto path = persistent_test_path();
    {
        ApiFixture fixture(corpus.value);
        auto client = persistent_client_for(fixture, path);
        (void)client.activate("strict-restart-key");
        client.close();
    }
    {
        ApiFixture outage(corpus.value);
        outage.persistent_mode = true;
        outage.offline_refresh = true;
        auto client = persistent_client_for(outage, path);
        expect_error([&] { (void)client.require_access("export"); }, ErrorKind::transient);
        expect_error([&] { (void)client.require_access("export"); }, ErrorKind::transient);
        require(outage.activation_calls == 0 && outage.validate_calls == 3,
                "strict outage must preserve activation and honor the refresh backoff");
        client.close();
    }
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
}

void test_persistent_transport_failure_keeps_activation(const Corpus& corpus) {
    FakeClock clock;
    const auto path = persistent_test_path();
    {
        ApiFixture fixture(corpus.value);
        auto client = persistent_client_for(fixture, path);
        (void)client.activate("tls-failure-key");
        client.close();
    }
    {
        ApiFixture failing(corpus.value);
        failing.persistent_mode = true;
        failing.tls_failure_refresh = true;
        auto client = persistent_client_for(failing, path);
        expect_error([&] { (void)client.require_access("export"); }, ErrorKind::transport_security);
        bool prompted = false;
        expect_error([&] {
            (void)client.ensure_access("export", [&]() -> std::optional<std::string> {
                prompted = true;
                return std::nullopt;
            });
        }, ErrorKind::transport_security);
        require(!prompted && failing.activation_calls == 0,
                "a transport failure must not ask for another licence key");
        client.close();
    }
    {
        ApiFixture recovered(corpus.value);
        recovered.persistent_mode = true;
        auto client = persistent_client_for(recovered, path);
        (void)client.require_access("export");
        require(recovered.activation_calls == 0,
                "a transport failure must not discard the saved activation");
        client.close();
    }
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
}

void test_persistent_close_discards_invalid_clock(const Corpus& corpus) {
    FakeClock clock;
    const auto path = persistent_test_path();
    {
        ApiFixture fixture(corpus.value);
        fixture.offline_activation = true;
        auto client = persistent_client_for(fixture, path);
        (void)client.activate("clock-checkpoint-key");
        clock.wall.fetch_sub(1);
        expect_error([&] { client.close(); }, ErrorKind::clock_uncertain);
        client.close();
    }
    auto setup = config();
    setup.installation_id.reset();
    {
        auto installed = open_installed_storage(setup, path);
        const auto record = persistent_codec::decode(
            setup, installed->provider(), *installed->load());
        require(record["access"].isNull() && !record["credential"].isNull(),
                "failed clock checkpoint must discard the grant durably and release the lease");
    }
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
}

void test_persistent_storage_format_and_contention() {
    Config setup = config();
    setup.installation_id.reset();
    const auto path = persistent_test_path();
    setup.installation_id = new_installation_id();
    auto record = persistent_codec::empty_record(setup, installed_provider());
    const auto bytes = persistent_codec::encode(setup, installed_provider(), record);
    auto decoded = persistent_codec::decode(setup, installed_provider(), bytes);
    require(decoded["format"].asInt() == 2 && decoded["credential"].isNull(),
            "format-2 initialization record must contain required nullable fields");
    require(decoded["installation"]["id"] == *setup.installation_id,
            "format-2 decode must preserve the existing installation ID");
    auto offline_record = decoded;
    offline_record["format"] = 3;
    offline_record["offline"] = Json::Value(Json::objectValue);
    offline_record["offline"]["jws"] = "a.b.c";
    offline_record["offline"]["sequence"] = 7;
    offline_record["offline"]["issuance_id"] = "offline_issue_7";
    offline_record["offline"]["content_digest"] = std::string(64, 'a');
    offline_record["offline"]["verified_at"] = Json::Int64{1800000000};
    offline_record["offline"]["time_high_water"] = Json::Int64{1800000010};
    offline_record["offline"]["wall_high_water"] = Json::Int64{1800000010};
    const auto offline_storage = persistent_codec::encode(setup, installed_provider(), offline_record);
    const auto decoded_offline = persistent_codec::decode(setup, installed_provider(), offline_storage);
    require(decoded_offline["format"] == 3 && decoded_offline["offline"]["sequence"] == 7,
            "format-3 offline record did not preserve signed-file floors");
    const auto offline_text = std::string(offline_storage.begin(), offline_storage.end());
    const auto offline_field = offline_text.find("\"offline\":{");
    require(offline_field != std::string::npos, "format-3 test record omitted offline object");
    auto duplicate_offline = offline_text;
    duplicate_offline.insert(offline_field, "\"offline\":{},");
    expect_error([&] { (void)persistent_codec::decode(setup, installed_provider(), duplicate_offline); },
                 ErrorKind::corrupt_state);
    auto malformed_offline = offline_record;
    malformed_offline["offline"]["unexpected"] = true;
    expect_error([&] { (void)persistent_codec::encode(setup, installed_provider(), malformed_offline); },
                 ErrorKind::corrupt_state);
    expect_error([&] {
        (void)persistent_codec::decode(setup, installed_provider() == "private_file"
            ? "windows_dpapi" : "private_file", bytes);
    }, ErrorKind::corrupt_state);
    auto changed_scope = setup;
    changed_scope.issuer += "/other";
    expect_error([&] { (void)persistent_codec::decode(changed_scope, installed_provider(), bytes); },
                 ErrorKind::corrupt_state);
    const std::string duplicate = "{\"sdk\":\"orbit.installed-client\",\"sdk\":\"tampered\"," +
        bytes.substr(bytes.find(',') + 1);
    expect_error([&] { (void)persistent_codec::decode(setup, installed_provider(), duplicate); },
                 ErrorKind::corrupt_state);

    {
        auto installed = open_installed_storage(setup, path);
        require(installed->initialization_needed(), "new store must request durable initialization");
        installed->initialize(bytes);
        expect_error([&] { (void)open_installed_storage(setup, path); },
                     ErrorKind::installation_in_use);
    }
    std::filesystem::remove(std::filesystem::path(path) / "orbit-installed.state");
    expect_error([&] { (void)open_installed_storage(setup, path); }, ErrorKind::corrupt_state);
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
}

void test_clock_anchor_bounds() {
    FakeClock clock;
    const auto elapsed = clock.elapsed.load();
    const auto wall = clock.wall.load();
    expect_error([&] { (void)ClockAnchor{-1, elapsed, wall}.now(); }, ErrorKind::clock_uncertain);
    expect_error([&] {
        (void)ClockAnchor{1, std::numeric_limits<std::int64_t>::min(), wall}.now();
    }, ErrorKind::clock_uncertain);

    clock.elapsed = std::numeric_limits<std::int64_t>::max();
    clock.wall = 0;
    expect_error([&] {
        (void)ClockAnchor{std::numeric_limits<std::int64_t>::max(), 0, 0}.now();
    }, ErrorKind::clock_uncertain);
    clock.wall = std::numeric_limits<std::int64_t>::max();
    expect_error([&] {
        (void)ClockAnchor{1, 0, std::numeric_limits<std::int64_t>::max()}.now();
    }, ErrorKind::clock_uncertain);
}

void test_pre_epoch_server_time(const Corpus& corpus) {
    ApiFixture fixture(corpus.value);
    fixture.pre_epoch_server_time = true;
    auto client = client_for(fixture);
    expect_error([&] { (void)client.activate("licence-key", "idempotency-123456"); },
                 ErrorKind::clock_uncertain);
    require(!fixture.storage->load().second,
            "pre-epoch server time must not establish a persisted activation");
}

void test_jwks_recovery_and_offline_clock(const Corpus& corpus) {
    FakeClock clock;
    ApiFixture fixture(corpus.value);
    fixture.forced_jwks_failures = 4;
    auto client = client_for(fixture);
    expect_error([&] { (void)client.activate("licence-key", "idempotency-123456"); }, ErrorKind::transient);
    require(fixture.jwks_calls == 3 && !fixture.storage->load().second,
            "transient key fetch must retry and must not persist an unverified first credential");
    auto recovered = client.activate("licence-key", "idempotency-123456");
    require(recovered.access == Access::online && fixture.storage->load().second,
            "activation should recover after a transient JWKS outage");

    ApiFixture offline_fixture(corpus.value);
    offline_fixture.offline_activation = true;
    auto offline_client = client_for(offline_fixture);
    require(offline_client.activate("licence-key", "idempotency-123456").access == Access::online,
            "offline-capable activation should start online");
    clock.advance(61);
    offline_fixture.offline_refresh = true;
    const auto offline = offline_client.require_access("export");
    require(offline.access == Access::offline && offline.has_feature("export"),
            "verified offline grant must authorize cached entitlements during a transient outage");
    clock.advance(840);
    require(offline_client.snapshot().access == Access::expired,
            "offline authority must expire at the signed grant deadline");
    clock.wall.fetch_sub(100);
    require(offline_client.snapshot().access == Access::refresh_required,
            "wall clock rollback must discard cached verified authority");

    ApiFixture strict_fixture(corpus.value);
    auto strict_client = client_for(strict_fixture);
    (void)strict_client.activate("strict-outage-key", "strict-outage-operation");
    clock.advance(61);
    strict_fixture.offline_refresh = true;
    int outage_prompts = 0;
    expect_error([&] {
        (void)strict_client.ensure_access("export", [&]() -> std::optional<std::string> {
            ++outage_prompts;
            return "must-not-be-requested";
        });
    }, ErrorKind::transient);
    require(outage_prompts == 0, "ensure_access must never prompt for a transient outage");
}

struct AccessMeasurement {
    double median_microseconds_per_operation = 0.0;
};

template <class Operation>
AccessMeasurement measure_access(Operation&& operation) {
    constexpr std::size_t batch_count = 5;
    constexpr std::size_t calls_per_batch = 10000;
    std::array<double, batch_count> batches{};
    for (auto& elapsed : batches) {
        const auto start = std::chrono::steady_clock::now();
        for (std::size_t index = 0; index < calls_per_batch; ++index) {
            const auto result = operation();
            require(result.access == Access::online && result.has_feature("export"),
                    "access benchmark observed a non-online result");
        }
        elapsed = std::chrono::duration<double, std::micro>(
            std::chrono::steady_clock::now() - start).count() / calls_per_batch;
    }
    std::sort(batches.begin(), batches.end());
    return {batches[batch_count / 2]};
}

const char* benchmark_platform() {
#if defined(_WIN32)
    return "Windows";
#elif defined(__APPLE__)
    return "macOS";
#elif defined(__linux__)
    return "Linux";
#else
    return "unknown";
#endif
}

const char* benchmark_architecture() {
#if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "arm64";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#else
    return "unknown";
#endif
}

int run_access_benchmark(const Corpus& corpus) {
    const auto path = persistent_test_path();
    try {
        ApiFixture fixture(corpus.value);
        auto client = persistent_client_for(fixture, path);
        require(client.activate("benchmark-access-key").access == Access::online,
                "access benchmark setup activation failed");
        for (int index = 0; index < 2000; ++index) {
            const auto guard = client.require_access("export");
            const auto snapshot = client.snapshot();
            require(guard.access == Access::online && snapshot.access == Access::online,
                    "access benchmark warmup failed");
        }

        const auto request_count = [&] {
            std::lock_guard<std::mutex> lock(fixture.mutex);
            return fixture.requests.size();
        };
        const auto requests_before = request_count();
        reset_access_benchmark_metrics();
        const auto guard = measure_access([&] { return client.require_access("export"); });
        const auto snapshot = measure_access([&] { return client.snapshot(); });
        require(request_count() == requests_before,
                "warm access loops must not increase HTTP request count");
        require(access_benchmark_storage_writes() == 0,
                "warm access loops must not write installed state");

        set_access_benchmark_invalidation_counting(true);
        constexpr std::size_t verification_calls = 500;
        for (std::size_t index = 0; index < verification_calls; ++index) {
            (void)client.require_access("export");
            (void)client.snapshot();
        }
        set_access_benchmark_invalidation_counting(false);
        const auto checks = access_benchmark_invalidation_checks();
        require(checks >= verification_calls * 2 && access_benchmark_storage_writes() == 0 &&
                    request_count() == requests_before,
                "every warm operation must retain its storage invalidation check without writing or HTTP");

        std::cout << "Access benchmark: platform=" << benchmark_platform()
                  << " arch=" << benchmark_architecture();
#ifdef NDEBUG
        std::cout << " build=Release";
#else
        std::cout << " build=Debug";
#endif
#if defined(__VERSION__)
        std::cout << " compiler=" << __VERSION__;
#elif defined(_MSC_VER)
        std::cout << " compiler=MSVC-" << _MSC_VER;
#else
        std::cout << " compiler=unknown";
#endif
#if defined(__GLIBCXX__)
            std::cout << " runtime=libstdc++-" << __GLIBCXX__;
#elif defined(_LIBCPP_VERSION)
            std::cout << " runtime=libc++-" << _LIBCPP_VERSION;
#endif
        std::cout << '\n'
                  << "RequireAccess: median " << guard.median_microseconds_per_operation
                  << " us/op (5 x 10000)\n"
                  << "Snapshot: median " << snapshot.median_microseconds_per_operation
                  << " us/op (5 x 10000)\n"
                  << "Warm-loop checks: installed-storage checks=" << checks
                  << "; storage writes=0; HTTP requests unchanged at " << requests_before << '\n';
        client.close();
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
        return 0;
    } catch (const std::exception& error) {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
        std::cerr << "Access benchmark failed: " << error.what() << '\n';
        return 1;
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        const auto corpus = load_corpus();
        if (argc == 2 && std::string_view(argv[1]) == "--benchmark-access") {
            return run_access_benchmark(corpus);
        }
        if (argc != 1) {
            std::cerr << "Usage: orbit_sdk_tests [--benchmark-access]\n";
            return 2;
        }
        const auto app_key_vectors = test_shared_app_key_vectors();
        test_fingerprint_options();
        test_strict_bounded_json();
        test_public_key_set_parsing();
        test_shared_grant_vectors(corpus);
        const auto session_vectors = test_shared_session_vectors();
        test_empty_explicit_activation_operation_ids(corpus);
        test_transport_retry_errors_and_cancellation();
        test_activation_accounts_and_proofs(corpus);
        test_owned_licence_offline_file_policy_bounds(corpus);
        test_public_timestamp_seconds_range();
        test_ensure_access_prompt_semantics(corpus);
        test_unauthenticated_generation_fences(corpus);
        test_clock_anchor_bounds();
        test_persistent_storage_format_and_contention();
        test_persistent_close_cancels_foreground(corpus);
        test_owner_cancellation_during_backoff();
        test_persistent_worker_stops_on_storage_failure(corpus);
        test_offline_worker_preserves_clock_uncertainty(corpus);
        test_offline_durable_import_fences(corpus);
#if defined(__linux__)
        test_installed_lease_replacement_fails_closed(corpus);
#endif
        test_persistent_invalid_cache_clock_recovers_credential(corpus);
        test_installed_identity_mismatch_rotates_installation(corpus);
#if defined(_WIN32)
        test_windows_interrupted_installed_write(corpus);
#endif
        test_persistent_close_discards_invalid_clock(corpus);
        test_persistent_strict_outage_is_not_activation_required(corpus);
        test_persistent_transport_failure_keeps_activation(corpus);
        test_persistent_online_restart_and_offline_recovery(corpus);
        test_installed_offline_file_lifecycle(corpus);
        test_installed_floating_session_lifecycle(corpus);
        test_online_meters_and_updates(corpus);
        test_floating_session_failures_and_generation_fences(corpus);
        test_offline_transition_floors(corpus);
        test_offline_identity_change_clears_file(corpus);
        test_offline_activation_logout_race(corpus);
        test_persistent_uncertain_activation_reuses_identity(corpus);
        test_persistent_account_activation_survives_failed_login(corpus);
        test_persistent_previous_rebind_and_expiry_contract(corpus);
        test_pre_epoch_server_time(corpus);
        test_jwks_recovery_and_offline_clock(corpus);
        test_logout_generation_fences_late_responses(corpus);
        std::cout << "C++ SDK tests passed (" << app_key_vectors
                  << " app-key vectors, 104 grant vectors, " << session_vectors
                  << " session vectors, fingerprint options, strict JSON, "
                     "transport, access, account and race cases).\n";
        return 0;
    } catch (const Error& error) {
        std::cerr << "C++ SDK error kind=" << static_cast<unsigned>(error.kind())
                  << " code=" << error.code() << '\n';
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "C++ SDK test failure: " << error.what() << '\n';
        return 1;
    }
}
