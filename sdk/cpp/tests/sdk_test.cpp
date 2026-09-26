#include "core.hpp"

#include "error.hpp"
#include "storage_windows.hpp"

#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>
#if defined(__linux__)
#include <sys/stat.h>
#endif

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace {

using namespace orbit;
using namespace orbit::detail;

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
    require(value["cases"].isArray() && value["cases"].size() == 101, "shared corpus must contain all 101 vectors");
    return {value, value["jwks"], value["expected"]};
}

std::string text(const Json::Value& value, const char* name) {
    require(value[name].isString(), std::string("missing string field ") + name);
    return value[name].asString();
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

std::string sign_test_token(const Json::Value& claims) {
    Json::Value header(Json::objectValue);
    header["alg"] = "ES256";
    header["typ"] = "orbit-access+jwt";
    header["kid"] = "test-key";
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
        value["now"].asInt64(),
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
    require(valid == 12 && invalid == 89, "grant corpus valid/invalid case counts changed");

    std::string strict_token;
    for (const auto& item : corpus.value["cases"]) {
        if (item["name"] == "strict-valid") strict_token = text(item, "token");
    }
    require(!strict_token.empty(), "strict-valid grant vector is missing");
    const auto wide_policy = token_with_claim(strict_token, "policy_version", Json::Int64{2147483648LL});
    const auto keys = GrantKeys::parse(corpus.jwks);
    const auto expected = vector_expected(corpus.expected);
    expect_error([&] { (void)keys.verify(wide_policy, expected); }, ErrorKind::invalid_response);
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
    std::optional<Json::Value> credential;

    std::uint64_t version() override {
        std::lock_guard<std::mutex> lock(mutex);
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
    std::atomic_bool offline_activation{false};
    std::atomic_bool persistent_mode{false};
    std::atomic_bool malformed_activation{false};
    std::atomic_bool finite_persistent_response{false};
    std::atomic_bool missing_expiry{false};
    std::atomic_bool pre_epoch_server_time{false};
    std::string last_activation_idempotency;
    std::string last_previous_credential;
    std::shared_ptr<Gate> activation_gate;
    std::shared_ptr<Gate> sessions_gate;
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
                if (malformed_activation.load()) return HttpResponse{200, R"({"bad":true})", {}};
                auto reply = activation_reply(corpus, offline_activation.load(), installation,
                    persistent_mode.load() && !finite_persistent_response.load());
                if (missing_expiry.load()) reply.removeMember("credential_expires_at");
                if (pre_epoch_server_time.load()) reply["server_time"] = "1969-12-31T23:59:59Z";
                return HttpResponse{200, encode_json(reply), {}};
            }
            if (route.find("/api/client/v1/activations/") == 0 && route.find("/validate") != std::string_view::npos) {
                ++validate_calls;
                if (offline_refresh.load()) return HttpResponse{503, "{}", "0"};
                Json::Value input_value = parse_json(body);
                const auto installation = input_value["installation_id"].asString();
                return HttpResponse{200, encode_json(activation_reply(
                    corpus, offline_activation.load(), installation, persistent_mode.load(), false)), {}};
            }
            if (route == "/api/client/v1/sessions") {
                if (sessions_gate) sessions_gate->block();
                require(method == "POST", "login method mismatch");
                Json::Value value(Json::objectValue);
                value["customer"] = Json::Value(Json::objectValue);
                value["customer"]["id"] = "customer_1";
                value["customer"]["username"] = "alice";
                value["customer"]["email"] = "alice@example.test";
                value["customer"]["suspended"] = false;
                value["customer"]["created_at"] = "2026-01-01T00:00:00Z";
                value["session"] = std::string(43, 's');
                value["expires_at"] = "2027-01-01T00:00:00Z";
                return HttpResponse{200, encode_json(value), {}};
            }
            if (route == "/api/client/v1/registrations") {
                if (registration_gate) registration_gate->block();
                Json::Value value(Json::objectValue);
                value["accepted"] = true;
                value["resend_credential"] = std::string(43, 'r');
                value["expires_at"] = "2027-01-01T00:00:00Z";
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
                page["items"].append(ApiFixture::sample_licence());
                page["next_cursor"] = "cursor_2";
                return HttpResponse{200, encode_json(page), {}};
            }
            if (route == "/api/client/v1/licence-claims") {
                require(method == "POST" && bearer_value.empty(), "licence claim leaked bearer header");
                return HttpResponse{200, encode_json(ApiFixture::sample_licence()), {}};
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

    static Json::Value sample_licence() {
        Json::Value licence(Json::objectValue);
        licence["id"] = "licence_1";
        licence["policy_name"] = "Standard";
        licence["state"] = "active";
        licence["expiry_mode"] = "never";
        licence["first_used_at"] = Json::nullValue;
        licence["expires_at"] = Json::nullValue;
        licence["duration_seconds"] = Json::Int64{3000000000LL};
        licence["device_limit"] = 1;
        licence["hwid_locked"] = false;
        licence["offline_allowed"] = true;
        licence["offline_seconds"] = 3600;
        licence["entitlements"] = Json::Value(Json::objectValue);
        licence["entitlements"]["export"] = true;
        return licence;
    }
};

Client client_for(ApiFixture& fixture) {
    return make_test_client(config(), Transport("https://example.test", fixture.handler()), fixture.storage);
}

std::string persistent_test_path() {
    return (std::filesystem::temp_directory_path() /
            ("orbit-cpp-installed-test-" + new_installation_id())).string();
}

Client persistent_client_for(ApiFixture& fixture, const std::string& path) {
    auto setup = config();
    setup.installation_id.reset();
    auto storage = open_installed_storage(setup, path);
    return make_test_installed_client(setup,
        Transport("https://example.test", fixture.handler()), std::move(storage));
}

void test_activation_accounts_and_proofs(const Corpus& corpus) {
    ApiFixture fixture(corpus.value);
    auto client = client_for(fixture);
    auto sibling = client;
    const auto activated = parse_json(client.activate("key-from-stdin", "idempotency-123456"));
    require(activated["access"].asString() == "online", "activation should produce online access");
    require(activated["entitlements"]["export"].asBool(), "verified export entitlement missing");
    const auto safe_snapshot = client.snapshot();
    require(safe_snapshot.find("bearer") == std::string::npos && safe_snapshot.find(std::string(43, 'c')) == std::string::npos,
            "snapshot exposed the private credential");
    require(fixture.storage->load().second.has_value(), "verified credential was not stored");
    require(client.require_access("export").find("online") != std::string::npos,
            "require_access should accept a current entitlement");
    Cancellation pre_cancelled;
    pre_cancelled.cancel();
    expect_error([&] { (void)client.require_access("export", &pre_cancelled); }, ErrorKind::cancelled);
    require(sibling.snapshot().find("online") != std::string::npos,
            "client copies should share current access state");

    static_assert(!std::is_copy_constructible<PendingRegistration>::value, "pending registrations must remain move-only");
    auto registration = client.register_customer("license-key", "alice", "alice@example.test", "correct horse battery");
    require(registration.metadata_json.find("accepted") != std::string::npos && registration.pending,
            "registration metadata/proof missing");
    client.resend_registration(registration.pending);
    auto other_client = client_for(fixture);
    expect_error([&] { other_client.resend_registration(registration.pending); }, ErrorKind::configuration);

    const auto logged_in = parse_json(client.login("alice", "password"));
    require(logged_in["customer"]["username"].asString() == "alice", "login metadata mismatch");
    require(client.customer_session_authorization() == "Bearer " + std::string(43, 's'),
            "customer proof mismatch");
    require(client.account().find(std::string(43, 's')) == std::string::npos,
            "account metadata exposed customer proof");
    const auto page = parse_json(client.owned_licences("cursor_1"));
    require(page["items"].size() == 1 && page["next_cursor"].asString() == "cursor_2",
            "owned licence metadata mismatch");
    require(page["items"][0]["duration_seconds"].asInt64() == 3000000000LL,
            "owned licence duration must preserve values above i32 range");
    const auto claimed = parse_json(client.claim_licence("claim-key", "claim-idempotency-123"));
    require(claimed["id"].asString() == "licence_1", "claim licence result mismatch");
    client.request_email_change("password", "new@example.test");
    client.request_password_recovery("alice@example.test");
    client.account_logout();
    require(client.account() == "null", "account logout did not clear local session");
    require(sibling.snapshot().find("denied") != std::string::npos,
            "client copies should observe logout state");
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
        client.local_logout();
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
        client.local_logout();
        fixture.sessions_gate->release();
        worker.join();
        require(result == static_cast<int>(ErrorKind::stale_response) && client.account() == "null",
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
            try { client.account_logout(); }
            catch (const Error& error) { result.store(static_cast<int>(error.kind())); }
        });
        fixture.logout_gate->wait_until_entered();
        require(client.account() == "null", "account logout must clear local metadata before network completion");
        expect_error([&] { (void)client.customer_session_authorization(); }, ErrorKind::reauthentication_required);
        (void)client.login("alice", "password");
        require(client.account().find("alice") != std::string::npos,
                "new account login must be visible while old logout is pending");
        fixture.logout_gate->release();
        worker.join();
        require(result == static_cast<int>(ErrorKind::stale_response) &&
                client.account().find("alice") != std::string::npos,
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
        const auto newer = parse_json(client.activate("key-from-stdin", "new-activation-idempotency"));
        require(newer["access"] == "online", "new activation must complete while deactivation is pending");
        fixture.deactivation_gate->release();
        worker.join();
        require(result == static_cast<int>(ErrorKind::stale_response) &&
                fixture.storage->load().second.has_value() &&
                parse_json(client.snapshot())["access"] == "online",
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
        const auto newer = parse_json(client.activate("key-from-stdin", "new-activation-idempotency"));
        require(newer["access"] == "online", "activation must complete while registration is pending");
        fixture.registration_gate->release();
        worker.join();
        require(result == static_cast<int>(ErrorKind::stale_response) &&
                fixture.storage->load().second.has_value() &&
                parse_json(client.snapshot())["access"] == "online",
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
        client.local_logout();
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
        client.local_logout();
        fixture.recovery_gate->release();
        worker.join();
        require(result == static_cast<int>(ErrorKind::stale_response),
                "late password recovery proof must be fenced by logout");
    }
}

struct FakeClock {
    std::atomic<std::int64_t> elapsed{100'000'000'000LL};
    std::atomic<std::int64_t> wall{1'700'000'000};
    FakeClock() {
        auto self = this;
        set_test_clock([self] {
            return std::make_pair(self->elapsed.load(), self->wall.load());
        });
    }
    ~FakeClock() { set_test_clock({}); }
    void advance(std::int64_t seconds) {
        elapsed.fetch_add(seconds * 1'000'000'000LL);
        wall.fetch_add(seconds);
    }
};

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
    std::optional<std::string> load() override { return wrapped_->load(); }
    void initialize(std::string_view bytes) override { wrapped_->initialize(bytes); }
    void save(std::string_view bytes) override {
        if (fail.load()) {
            ++failed_writes;
            throw Error(1, ErrorKind::storage, "installation_state_write_failed", {});
        }
        wrapped_->save(bytes);
    }
    std::string_view provider() const noexcept override { return wrapped_->provider(); }
    std::atomic_bool fail{false};
    std::atomic_int failed_writes{0};
private:
    std::shared_ptr<InstalledStorage> wrapped_;
};

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
            const auto snapshot = parse_json(reopened.snapshot());
            require(snapshot["access"] == (outage ? "refresh_required" : "online") &&
                        !snapshot["reauthentication_required"].asBool() &&
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
                require(parse_json(online.snapshot())["access"] == "online" && recovery.activation_calls == 0,
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
        const auto activated = parse_json(client.activate("persistent-license-key"));
        require(activated["access"] == "online" &&
                    activated["credential_expires_at"].isNull(),
                "persistent activation must explicitly negotiate a null credential expiry");
        require(first.persistent_mode.load() && first.activation_calls == 1,
                "key-first activation must request persistent credential mode");
        original_expiry = json_int64(activated["expires_at"]);
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
        const auto state = parse_json(client.snapshot());
        require(state["access"] == "online" &&
                    json_int64(state["expires_at"]) == original_expiry,
                "online restart must retain the original signed grant deadline");
        client.close();
    }
    {
        ApiFixture offline(corpus.value);
        offline.persistent_mode = true;
        offline.offline_activation = true;
        offline.offline_refresh = true;
        auto client = persistent_client_for(offline, path);
        const auto state = parse_json(client.snapshot());
        require(offline.validate_calls == 3 && state["access"] == "offline" &&
                    json_int64(state["expires_at"]) == original_expiry,
                "transient validation may restore only the original offline-enabled grant");
        require(parse_json(client.require_access("export"))["access"] == "offline",
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
    auto recovered = parse_json(client.activate("licence-key", "idempotency-123456"));
    require(recovered["access"].asString() == "online" && fixture.storage->load().second,
            "activation should recover after a transient JWKS outage");

    ApiFixture offline_fixture(corpus.value);
    offline_fixture.offline_activation = true;
    auto offline_client = client_for(offline_fixture);
    require(parse_json(offline_client.activate("licence-key", "idempotency-123456"))["access"] == "online",
            "offline-capable activation should start online");
    clock.advance(61);
    offline_fixture.offline_refresh = true;
    const auto offline = parse_json(offline_client.require_access("export"));
    require(offline["access"].asString() == "offline" && offline["entitlements"]["export"].asBool(),
            "verified offline grant must authorize cached entitlements during a transient outage");
    clock.advance(840);
    require(parse_json(offline_client.snapshot())["access"].asString() == "expired",
            "offline authority must expire at the signed grant deadline");
    clock.wall.fetch_sub(100);
    require(parse_json(offline_client.snapshot())["access"].asString() == "refresh_required",
            "wall clock rollback must discard cached verified authority");
}

} // namespace

int main() {
    try {
        const auto corpus = load_corpus();
        test_strict_bounded_json();
        test_shared_grant_vectors(corpus);
        test_transport_retry_errors_and_cancellation();
        test_activation_accounts_and_proofs(corpus);
        test_unauthenticated_generation_fences(corpus);
        test_clock_anchor_bounds();
        test_persistent_storage_format_and_contention();
        test_persistent_close_cancels_foreground(corpus);
        test_owner_cancellation_during_backoff();
        test_persistent_worker_stops_on_storage_failure(corpus);
        test_persistent_invalid_cache_clock_recovers_credential(corpus);
#if defined(_WIN32)
        test_windows_interrupted_installed_write(corpus);
#endif
        test_persistent_close_discards_invalid_clock(corpus);
        test_persistent_strict_outage_is_not_activation_required(corpus);
        test_persistent_online_restart_and_offline_recovery(corpus);
        test_persistent_uncertain_activation_reuses_identity(corpus);
        test_persistent_previous_rebind_and_expiry_contract(corpus);
        test_pre_epoch_server_time(corpus);
        test_jwks_recovery_and_offline_clock(corpus);
        test_logout_generation_fences_late_responses(corpus);
        std::cout << "C++ SDK tests passed (101 grant vectors, strict JSON, transport, access, account and race cases).\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "C++ SDK test failure: " << error.what() << '\n';
        return 1;
    }
}
