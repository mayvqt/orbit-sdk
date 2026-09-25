#include "orbit_sdk.hpp"

#include "json.hpp"
#include "platform.hpp"
#include "platform_test_support.hpp"
#include "storage_codec.hpp"
#include "storage_linux.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

namespace {

void require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

orbit::Config sample_config() {
    orbit::Config config;
    config.api_origin = "https://example.test";
    config.issuer = "https://example.test";
    config.application_id = "app";
    config.environment_id = "test";
    config.installation_id = "synthetic_installation";
    config.fingerprint = orbit::Fingerprint{std::string(64, 'a'), "custom:synthetic"};
    return config;
}

Json::Value sample_credential() {
    Json::Value credential(Json::objectValue);
    credential["activation_id"] = "synthetic_activation";
    credential["licence_id"] = "synthetic_licence";
    credential["bearer"] = std::string(43, 's');
    credential["expires_at"] = Json::Int64(1234);
    return credential;
}

std::string legacy_record_fixture(std::uint64_t generation = 7) {
    auto record = "{\"sdk\":\"orbit.rust.storage\",\"format\":1,"
           "\"generation\":7,\"issuer\":\"https://example.test\","
           "\"application_id\":\"app\",\"environment_id\":\"test\","
           "\"installation_id\":\"synthetic_installation\","
           "\"fingerprint\":\"" + std::string(64, 'a') +
           "\",\"fingerprint_provider\":\"custom:synthetic\","
           "\"credential\":{\"activation_id\":\"synthetic_activation\","
           "\"licence_id\":\"synthetic_licence\",\"bearer\":\"" +
           std::string(43, 's') +
           "\",\"expires_at\":1234}}";
    const auto generation_field = record.find("\"generation\":7");
    record.replace(generation_field, std::string("\"generation\":7").size(),
                   "\"generation\":" + std::to_string(generation));
    return record;
}

#if defined(__linux__)
void append_u32_be(std::string& bytes, std::uint32_t value) {
    bytes.push_back(static_cast<char>((value >> 24) & 0xff));
    bytes.push_back(static_cast<char>((value >> 16) & 0xff));
    bytes.push_back(static_cast<char>((value >> 8) & 0xff));
    bytes.push_back(static_cast<char>(value & 0xff));
}

std::string expected_secret_service_scope(const orbit::Config& config,
                                          std::string_view directory) {
    std::string entropy_preimage("orbit.sdk.storage.v1\0", 21);
    for (const auto* value : {&config.issuer, &config.application_id,
                              &config.environment_id, &*config.installation_id}) {
        append_u32_be(entropy_preimage, static_cast<std::uint32_t>(value->size()));
        entropy_preimage.append(*value);
    }
    std::array<unsigned char, 32> entropy{};
    unsigned int digest_length = 0;
    require(EVP_Digest(entropy_preimage.data(), entropy_preimage.size(), entropy.data(),
                       &digest_length, EVP_sha256(), nullptr) == 1 &&
                digest_length == entropy.size(),
            "could not compute independent storage entropy fixture");

    std::string item_preimage("orbit.sdk.secret-service.v1\0", 28);
    append_u32_be(item_preimage, 4);
    item_preimage.append("rust", 4);
    item_preimage.append(reinterpret_cast<const char*>(entropy.data()), entropy.size());
    append_u32_be(item_preimage, static_cast<std::uint32_t>(directory.size()));
    item_preimage.append(directory);
    std::array<unsigned char, 32> digest{};
    require(EVP_Digest(item_preimage.data(), item_preimage.size(), digest.data(),
                       &digest_length, EVP_sha256(), nullptr) == 1 &&
                digest_length == digest.size(),
            "could not compute independent Secret Service scope fixture");
    static constexpr char hex[] = "0123456789abcdef";
    std::string output;
    output.reserve(digest.size() * 2);
    for (const auto byte : digest) {
        output.push_back(hex[byte >> 4]);
        output.push_back(hex[byte & 15]);
    }
    return output;
}
#endif

void test_installation_id_and_fingerprint_vectors() {
    const auto first = orbit::new_installation_id();
    const auto second = orbit::new_installation_id();
    const auto valid_installation = [](std::string_view value) {
        return value.size() == 32 && std::all_of(value.begin(), value.end(), [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '-' || c == '_';
        });
    };
    require(valid_installation(first) && valid_installation(second) && first != second,
            "installation IDs must be random base64url values");

    const auto fingerprint = orbit::machine_fingerprint(
        "app", "test", "linux", " \t\r\n00112233-4455-6677-8899-AABBCCDDEEFF\v\f ");
    require(fingerprint == "d5166cf3cc8ff5218fb7744aac272ea6f4cb4e75598e2851787d24e107fd05a0",
            "machine fingerprint must match the shared SHA-256 framing vector");
    require(orbit::machine_fingerprint("app", "test", "windows",
                                       "00112233445566778899aabbccddeeff") != fingerprint,
            "OS family must be included in the machine fingerprint");
    for (const auto identity : {"", "00000000000000000000000000000000",
                                "ffffffffffffffffffffffffffffffff",
                                "00112233445566778899aabbccddeefg",
                                "00112233 445566778899aabbccddeeff"}) {
        bool rejected = false;
        try {
            (void)orbit::machine_fingerprint("app", "test", "linux", identity);
        } catch (const orbit::Error& error) {
            rejected = error.kind() == orbit::ErrorKind::denied &&
                       error.code() == "device_identity_unavailable";
        }
        require(rejected, "invalid machine identities must fail closed");
    }
}

std::vector<unsigned char> smbios_system_record() {
    std::vector<unsigned char> record{1, 25, 0, 0, 1, 2, 3, 4};
    const unsigned char uuid[] = {
        0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    record.insert(record.end(), std::begin(uuid), std::end(uuid));
    record.push_back(6);
    const char strings[] = "manufacturer\0product\0version\0serial\0\0";
    record.insert(record.end(), strings, strings + sizeof(strings) - 1);
    return record;
}

std::string smbios_table(std::vector<unsigned char> payload) {
    std::string raw{static_cast<char>(0), static_cast<char>(3),
                    static_cast<char>(8), static_cast<char>(0)};
    const auto size = static_cast<std::uint32_t>(payload.size());
    for (unsigned int i = 0; i < 4; ++i) {
        raw.push_back(static_cast<char>((size >> (8 * i)) & 0xff));
    }
    raw.append(reinterpret_cast<const char*>(payload.data()), payload.size());
    return raw;
}

void test_smbios_fixture_parser() {
    const std::vector<unsigned char> end{127, 4, 0xff, 0xff, 0, 0};
    auto payload = smbios_system_record();
    payload.insert(payload.end(), end.begin(), end.end());
    const auto valid = smbios_table(payload);
    const auto uuid = orbit::detail::testing::parse_smbios_uuid(valid);
    require(uuid && *uuid == "00112233-4455-6677-8899-aabbccddeeff",
            "SMBIOS Type 1 UUID byte order must be normalized");

    auto too_old = valid;
    too_old[1] = 2;
    too_old[2] = 5;
    require(!orbit::detail::testing::parse_smbios_uuid(too_old),
            "SMBIOS versions older than 2.6 must fail");
    auto wrong_length = valid;
    wrong_length[4] = static_cast<char>(static_cast<unsigned char>(wrong_length[4]) + 1);
    require(!orbit::detail::testing::parse_smbios_uuid(wrong_length),
            "SMBIOS declared table size must be exact");
    require(!orbit::detail::testing::parse_smbios_uuid(valid.substr(0, valid.size() - 1)),
            "SMBIOS truncated strings and end records must fail");
    require(!orbit::detail::testing::parse_smbios_uuid(smbios_table(end)),
            "SMBIOS needs exactly one complete Type 1 identity");
    auto duplicate = smbios_system_record();
    const auto second = smbios_system_record();
    duplicate.insert(duplicate.end(), second.begin(), second.end());
    duplicate.insert(duplicate.end(), end.begin(), end.end());
    require(!orbit::detail::testing::parse_smbios_uuid(smbios_table(duplicate)),
            "duplicate SMBIOS Type 1 records must fail");
    for (const auto invalid : {0, 0xff}) {
        auto unavailable = payload;
        std::fill(unavailable.begin() + 8, unavailable.begin() + 24,
                  static_cast<unsigned char>(invalid));
        require(!orbit::detail::testing::parse_smbios_uuid(smbios_table(unavailable)),
                "unavailable SMBIOS UUID markers must fail");
    }
}

void test_native_clock() {
    const auto elapsed = orbit::detail::elapsed_nanoseconds();
    const auto wall = orbit::detail::wall_seconds();
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    require(elapsed > 0 && orbit::detail::elapsed_nanoseconds() >= elapsed,
            "native suspend-aware elapsed clock must be monotonic");
    require(wall > 1'700'000'000 && orbit::detail::wall_seconds() >= wall,
            "native wall clock must return Unix seconds");
}

void test_storage_codec_legacy_record_and_versions() {
    auto config = sample_config();
    const auto fixture = legacy_record_fixture();
    const auto decoded = orbit::detail::storage_codec::decode(config, fixture);
    require(decoded.first == 7 && decoded.second &&
                (*decoded.second)["activation_id"].asString() == "synthetic_activation" &&
                (*decoded.second)["bearer"].asString() == std::string(43, 's'),
            "Rust-format credential records must load without migration");

    const auto encoded = orbit::detail::storage_codec::encode(config, 8, decoded.second);
    const auto roundtrip = orbit::detail::storage_codec::decode(config, encoded);
    require(roundtrip.first == 8 && roundtrip.second &&
                (*roundtrip.second)["licence_id"].asString() == "synthetic_licence" &&
                encoded == legacy_record_fixture(8),
            "native codec must preserve the Rust byte order and record fields");
    const auto maximum = orbit::detail::storage_codec::encode(
        config, orbit::detail::storage_codec::max_generation, std::nullopt);
    require(orbit::detail::storage_codec::decode(config, maximum).first ==
                orbit::detail::storage_codec::max_generation,
            "codec must accept the previous signed generation maximum");

    bool bad_generation = false;
    try {
        (void)orbit::detail::storage_codec::encode(
            config, orbit::detail::storage_codec::max_generation + 1, std::nullopt);
    } catch (const orbit::Error& error) {
        bad_generation = error.kind() == orbit::ErrorKind::storage;
    }
    require(bad_generation, "codec must reject generations beyond signed range");

    auto wrong_scope = config;
    wrong_scope.issuer.push_back('/');
    bool scope_rejected = false;
    try {
        (void)orbit::detail::storage_codec::decode(wrong_scope, fixture);
    } catch (const orbit::Error& error) {
        scope_rejected = error.kind() == orbit::ErrorKind::storage;
    }
    require(scope_rejected, "codec must reject a different issuer scope");

    const auto original = orbit::detail::parse_json(fixture);
    const auto rejects_record = [&](Json::Value changed) {
        try {
            (void)orbit::detail::storage_codec::decode(
                config, orbit::detail::encode_json(changed));
            return false;
        } catch (const orbit::Error& error) {
            return error.kind() == orbit::ErrorKind::storage;
        }
    };
    for (const auto& change : std::vector<std::pair<std::string, Json::Value>>{
             {"sdk", Json::Value("orbit.other.storage")},
             {"format", Json::Value(2)},
             {"format", Json::Value(1.0)},
             {"generation", Json::Value(-1)},
             {"generation", Json::Value(Json::UInt64(
                  orbit::detail::storage_codec::max_generation + 1))},
             {"generation", Json::Value(1.5)},
             {"generation", Json::Value(7.0)},
             {"generation", Json::Value("7")},
             {"credential", Json::Value(Json::arrayValue)}}) {
        auto changed = original;
        changed[change.first] = change.second;
        require(rejects_record(std::move(changed)),
                "codec must reject wrong scope, format, and generation types");
    }
    for (const auto* field : {"sdk", "format", "generation", "issuer",
                              "application_id", "environment_id",
                              "installation_id", "fingerprint",
                              "fingerprint_provider", "credential"}) {
        auto changed = original;
        changed.removeMember(field);
        require(rejects_record(std::move(changed)),
                "codec must reject records missing required fields");
    }
    {
        auto changed = original;
        changed["unexpected"] = true;
        require(rejects_record(std::move(changed)),
                "codec must reject unknown top-level storage fields");
    }
    for (const auto& change : std::vector<std::pair<std::string, Json::Value>>{
             {"activation_id", Json::Value("")},
             {"licence_id", Json::Value("invalid id")},
             {"bearer", Json::Value(std::string(42, 's'))},
             {"bearer", Json::Value(std::string(43, '/'))},
             {"expires_at", Json::Value(Json::nullValue)},
             {"expires_at", Json::Value(1234.0)},
             {"unexpected", Json::Value(true)}}) {
        auto changed = original;
        changed["credential"][change.first] = change.second;
        require(rejects_record(std::move(changed)),
                "codec must reject credential tampering and type changes");
    }

    auto duplicate = fixture;
    duplicate.pop_back();
    duplicate += ",\"format\":1}";
    bool duplicate_rejected = false;
    try {
        (void)orbit::detail::storage_codec::decode(config, duplicate);
    } catch (const orbit::Error& error) {
        duplicate_rejected = error.kind() == orbit::ErrorKind::storage;
    }
    require(duplicate_rejected, "codec parser must reject duplicate JSON fields");

    orbit::Config memory_config;
    const auto memory = orbit::detail::open_storage(memory_config);
    require(memory->version() == 0 && !memory->load().second,
            "memory storage must start at generation zero");
    memory->save(0, sample_credential());
    require(memory->load().second.has_value(), "memory storage must save credentials");
    bool stale_rejected = false;
    try {
        memory->save(9, sample_credential());
    } catch (const orbit::Error& error) {
        stale_rejected = error.kind() == orbit::ErrorKind::stale_response;
    }
    require(stale_rejected && memory->invalidate() == 1 && !memory->load().second,
            "compare-and-save and invalidation tombstones must fence stale writes");
}

#if defined(__linux__)

class LinuxFixture {
public:
    LinuxFixture() {
        std::string pattern = "/tmp/orbit-cpp-platform-test-XXXXXX";
        auto* created = ::mkdtemp(pattern.data());
        if (created == nullptr) {
            throw std::runtime_error("could not create platform test fixture");
        }
        root_ = created;
        storage_ = root_ + "/storage";
        if (::mkdir(storage_.c_str(), 0700) != 0) {
            throw std::runtime_error("could not create protected storage fixture");
        }
        helper_ = root_ + "/fake-secret-tool";
        const std::string script =
            "#!/bin/sh\n"
            "printf '%s\\n' \"$@\" >> \"$ORBIT_CPP_TEST_HELPER_ARGS\"\n"
            "case \"$ORBIT_CPP_TEST_HELPER_MODE:$1\" in\n"
            "  timeout:lookup) exec /bin/sleep 30 ;;\n"
            "  timeout_descendant:lookup) /bin/sleep 30 & echo $! > \"$ORBIT_CPP_TEST_HELPER_CHILD\"; exit 0 ;;\n"
            "  fail_lookup:lookup) exit 2 ;;\n"
            "  stdout_exit_one:lookup) printf diagnostic; exit 1 ;;\n"
            "  diagnostic_lookup:lookup) printf diagnostic >&2; exit 1 ;;\n"
            "  invalid_record:lookup) printf 'Zh==\\n'; exit 0 ;;\n"
            "  large_output:lookup) head -c 5466 /dev/zero; exit 0 ;;\n"
            "  fail_store:store) exit 2 ;;\n"
            "  *:lookup) [ -f \"$ORBIT_CPP_TEST_HELPER_STATE\" ] || exit 1; cat \"$ORBIT_CPP_TEST_HELPER_STATE\"; printf '\\n' ;;\n"
            "  *:store) cat > \"$ORBIT_CPP_TEST_HELPER_STATE\" ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n";
        std::ofstream output(helper_, std::ios::binary);
        output << script;
        output.close();
        if (::chmod(helper_.c_str(), 0700) != 0) {
            throw std::runtime_error("could not make synthetic helper executable");
        }
        state_ = root_ + "/synthetic-keyring-item";
        args_ = root_ + "/helper-arguments";
        child_pid_ = root_ + "/helper-child-pid";
        ::setenv("ORBIT_CPP_TEST_HELPER_STATE", state_.c_str(), 1);
        ::setenv("ORBIT_CPP_TEST_HELPER_ARGS", args_.c_str(), 1);
        ::setenv("ORBIT_CPP_TEST_HELPER_CHILD", child_pid_.c_str(), 1);
        ::setenv("ORBIT_CPP_TEST_HELPER_MODE", "normal", 1);
    }
    ~LinuxFixture() {
        ::unsetenv("ORBIT_CPP_TEST_HELPER_STATE");
        ::unsetenv("ORBIT_CPP_TEST_HELPER_ARGS");
        ::unsetenv("ORBIT_CPP_TEST_HELPER_CHILD");
        ::unsetenv("ORBIT_CPP_TEST_HELPER_MODE");
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }
    LinuxFixture(const LinuxFixture&) = delete;
    LinuxFixture& operator=(const LinuxFixture&) = delete;

    const std::string& root() const { return root_; }
    const std::string& storage() const { return storage_; }
    const std::string& helper() const { return helper_; }
    const std::string& state() const { return state_; }
    const std::string& args() const { return args_; }
    const std::string& child_pid() const { return child_pid_; }
    void mode(const char* value) { ::setenv("ORBIT_CPP_TEST_HELPER_MODE", value, 1); }

    orbit::Config config() const {
        auto value = sample_config();
        value.storage.mode = orbit::StorageMode::linux_secret_service;
        value.storage.path = storage_;
        return value;
    }

private:
    std::string root_;
    std::string storage_;
    std::string helper_;
    std::string state_;
    std::string args_;
    std::string child_pid_;
};

bool storage_failure(const std::function<void()>& call) {
    try {
        call();
    } catch (const orbit::Error& error) {
        return error.kind() == orbit::ErrorKind::storage;
    }
    return false;
}

bool helper_process_running(long pid) {
    std::ifstream status("/proc/" + std::to_string(pid) + "/stat");
    std::string line;
    if (!std::getline(status, line)) {
        return false;
    }
    const auto command_end = line.rfind(')');
    return command_end != std::string::npos && command_end + 2 < line.size() &&
           line[command_end + 2] != 'Z' && line[command_end + 2] != 'X';
}

void test_linux_secret_service_fake_helper_roundtrip() {
    LinuxFixture fixture;
    auto config = fixture.config();
    auto storage = orbit::detail::storage_linux::open(config, fixture.helper());
    require(storage->version() == 0 && !storage->load().second,
            "new Secret Service scope must persist its generation-zero tombstone");
    require(storage_failure([&] {
                (void)orbit::detail::storage_linux::open(config, fixture.helper());
            }), "an exclusive lease must reject a second opener");

    storage->save(0, sample_credential());
    auto loaded = storage->load();
    require(loaded.first == 0 && loaded.second &&
                (*loaded.second)["bearer"].asString() == std::string(43, 's'),
            "Secret Service storage must compare and cache a saved credential");
    std::ifstream item(fixture.state(), std::ios::binary);
    const std::string encoded_item((std::istreambuf_iterator<char>(item)), {});
    require(!encoded_item.empty() &&
                encoded_item.find(std::string(43, 's')) == std::string::npos,
            "fake keyring fixture must receive the canonical base64 record");
    bool stale_rejected = false;
    try {
        storage->save(1, sample_credential());
    } catch (const orbit::Error& error) {
        stale_rejected = error.kind() == orbit::ErrorKind::stale_response;
    }
    require(stale_rejected && storage->invalidate() == 1 && !storage->load().second,
            "Secret Service invalidation must persist a tombstone");
    storage.reset();

    storage = orbit::detail::storage_linux::open(config, fixture.helper());
    require(storage->version() == 1 && !storage->load().second,
            "Secret Service tombstones must survive process-style reopen");
    storage.reset();
    std::filesystem::remove(fixture.state());
    require(storage_failure([&] {
                (void)orbit::detail::storage_linux::open(config, fixture.helper());
            }), "missing existing keyring state must never reset the generation");

    std::ifstream args(fixture.args());
    const std::string arguments((std::istreambuf_iterator<char>(args)), {});
    const auto marker = arguments.rfind("scope\n");
    require(marker != std::string::npos, "helper arguments must include a scoped item");
    const auto scope_begin = marker + std::string("scope\n").size();
    const auto scope_end = arguments.find('\n', scope_begin);
    require(scope_end != std::string::npos, "helper scope argument must be terminated");
    const auto passed_scope = arguments.substr(scope_begin, scope_end - scope_begin);
    require(arguments.find("--label=Orbit Rust SDK activation") != std::string::npos &&
                passed_scope == expected_secret_service_scope(config, fixture.storage()) &&
                arguments.find(std::string(43, 's')) == std::string::npos,
            "helper arguments must preserve the Rust item scope without bearer data");
}

void test_linux_helper_timeout_and_poisoned_pending_marker() {
    for (const auto* mode : {"fail_lookup", "stdout_exit_one", "diagnostic_lookup",
                             "invalid_record", "large_output"}) {
        LinuxFixture fixture;
        fixture.mode(mode);
        require(storage_failure([&] {
                    (void)orbit::detail::storage_linux::open(fixture.config(), fixture.helper());
                }), "helper errors, malformed records, and oversized output must fail closed");
    }
    {
        LinuxFixture fixture;
        fixture.mode("timeout");
        const auto started = std::chrono::steady_clock::now();
        require(storage_failure([&] {
                    (void)orbit::detail::storage_linux::open(
                        fixture.config(), fixture.helper(), std::chrono::milliseconds(100));
                }), "helper timeouts must fail as storage errors");
        require(std::chrono::steady_clock::now() - started < std::chrono::seconds(2),
                "helper timeout must kill and reap the synthetic process group");
    }
    {
        LinuxFixture fixture;
        fixture.mode("timeout_descendant");
        const auto started = std::chrono::steady_clock::now();
        require(storage_failure([&] {
                    (void)orbit::detail::storage_linux::open(
                        fixture.config(), fixture.helper(), std::chrono::milliseconds(100));
                }), "a descendant retaining helper pipes must time out");
        require(std::chrono::steady_clock::now() - started < std::chrono::seconds(2),
                "descendant-held pipes must not extend the helper deadline");
        std::ifstream pid_file(fixture.child_pid());
        long child_pid = 0;
        pid_file >> child_pid;
        require(child_pid > 0, "fake helper must record the descendant pid");
        const auto cleanup_deadline = std::chrono::steady_clock::now() +
                                      std::chrono::seconds(1);
        while (helper_process_running(child_pid) &&
               std::chrono::steady_clock::now() < cleanup_deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        require(!helper_process_running(child_pid),
                "timed-out helper descendants must be killed with their owned group");
    }
    {
        LinuxFixture fixture;
        fixture.mode("fail_store");
        require(storage_failure([&] {
                    (void)orbit::detail::storage_linux::open(fixture.config(), fixture.helper());
                }), "a failed initial keyring write must fail open");
        std::ifstream marker(fixture.storage() + "/orbit-storage.lock", std::ios::binary);
        const std::string pending((std::istreambuf_iterator<char>(marker)), {});
        require(pending.size() == 1 && static_cast<unsigned char>(pending[0]) == 1,
                "failed writes must leave a flushed pending marker");
        std::ifstream before_file(fixture.args());
        const std::string before((std::istreambuf_iterator<char>(before_file)), {});
        fixture.mode("normal");
        require(storage_failure([&] {
                    (void)orbit::detail::storage_linux::open(fixture.config(), fixture.helper());
                }), "pending writes must poison reopening before helper access");
        std::ifstream after_file(fixture.args());
        const std::string after((std::istreambuf_iterator<char>(after_file)), {});
        require(after == before, "pending marker recovery must not call the fake helper");
    }
}

void test_linux_private_directory_and_lease_replacement() {
    LinuxFixture fixture;
    auto config = fixture.config();
    const auto link = fixture.root() + "/link";
    std::filesystem::create_directory_symlink(fixture.storage(), link);
    auto linked = config;
    linked.storage.path = link;
    require(storage_failure([&] {
                (void)orbit::detail::storage_linux::open(linked, fixture.helper());
            }), "storage paths must reject symlink traversal");

    require(::chmod(fixture.storage().c_str(), 0755) == 0,
            "could not prepare public-mode test directory");
    require(storage_failure([&] {
                (void)orbit::detail::storage_linux::open(config, fixture.helper());
            }), "storage directories must remain private to the current user");
    require(::chmod(fixture.storage().c_str(), 0700) == 0,
            "could not restore private test directory mode");

    auto storage = orbit::detail::storage_linux::open(config, fixture.helper());
    const auto lease_path = fixture.storage() + "/orbit-storage.lock";
    require(::unlink(lease_path.c_str()) == 0, "could not replace synthetic lease");
    const int replacement = ::open(lease_path.c_str(), O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC,
                                   0600);
    require(replacement >= 0, "could not create replacement synthetic lease");
    ::close(replacement);
    require(storage_failure([&] { (void)storage->version(); }),
            "an active storage object must detect a replaced lease inode");
    require(storage_failure([&] { (void)storage->load(); }),
            "a replaced lease must poison cached credentials");
}

#endif // __linux__

#if defined(_WIN32)

class ScopedUserProfileOverride {
public:
    ScopedUserProfileOverride() {
        const auto required = GetEnvironmentVariableW(L"USERPROFILE", nullptr, 0);
        require(required > 0 && required < 32768, "USERPROFILE must be available");
        original_.resize(required);
        const auto length = GetEnvironmentVariableW(
            L"USERPROFILE", original_.data(), required);
        require(length > 0 && length < required, "USERPROFILE must be readable");
        original_.resize(length);
        require(SetEnvironmentVariableW(L"USERPROFILE", L"C:\\orbit-unused-profile") != 0,
                "could not set synthetic USERPROFILE for path compatibility test");
        active_ = true;
    }
    ~ScopedUserProfileOverride() {
        if (active_) {
            (void)SetEnvironmentVariableW(L"USERPROFILE", original_.c_str());
        }
    }

private:
    std::wstring original_;
    bool active_ = false;
};

class WindowsFixture {
public:
    WindowsFixture() {
        std::array<wchar_t, 32768> temporary{};
        const auto length = GetTempPathW(static_cast<DWORD>(temporary.size()),
                                         temporary.data());
        require(length > 0 && length < temporary.size(), "private temporary path must be available");
        const auto suffix = orbit::new_installation_id();
        path_ = std::filesystem::path(std::wstring(temporary.data(), length)) /
                std::filesystem::path(L"orbit-cpp-platform-test-") /
                std::filesystem::path(std::wstring(suffix.begin(), suffix.end()));
        std::filesystem::create_directories(path_);
    }
    ~WindowsFixture() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    std::string path_utf8() const { return path_.u8string(); }
    std::filesystem::path path() const { return path_; }
    orbit::Config config() const {
        auto value = sample_config();
        value.storage.mode = orbit::StorageMode::windows_dpapi;
        value.storage.path = path_utf8();
        return value;
    }
private:
    std::filesystem::path path_;
};

void test_windows_dpapi_storage_rename_name_lengths() {
    WindowsFixture fixture;
    ScopedUserProfileOverride profile_override;
    for (std::size_t length = 1; length <= 8; ++length) {
        const auto name = std::wstring(length, L'x');
        const auto directory = fixture.path() / name;
        std::filesystem::create_directories(directory);
        auto config = fixture.config();
        config.storage.path = directory.u8string();

        auto storage = orbit::detail::open_storage(config);
        require(storage->version() == 0 && !storage->load().second,
                "Windows storage must initialize each rename-name fixture");
        storage->save(0, sample_credential());
        storage.reset();

        storage = orbit::detail::open_storage(config);
        const auto reopened = storage->load();
        require(reopened.first == 0 && reopened.second &&
                    (*reopened.second)["activation_id"].asString() ==
                        "synthetic_activation",
                "Windows storage must reopen each rename-name fixture");
        require(storage->invalidate() == 1,
                "Windows storage must invalidate each rename-name fixture");
        storage.reset();

        storage = orbit::detail::open_storage(config);
        require(storage->version() == 1 && !storage->load().second,
                "Windows storage tombstones must survive each rename-name fixture");
        storage.reset();
    }
}

void test_windows_dpapi_storage_roundtrip_and_missing_state() {
    WindowsFixture fixture;
    ScopedUserProfileOverride profile_override;
    const auto config = fixture.config();
    auto storage = orbit::detail::open_storage(config);
    require(storage->version() == 0 && !storage->load().second,
            "Windows DPAPI storage must initialize a generation-zero tombstone");
    bool lease_rejected = false;
    try {
        (void)orbit::detail::open_storage(config);
    } catch (const orbit::Error& error) {
        lease_rejected = error.kind() == orbit::ErrorKind::storage;
    }
    require(lease_rejected, "Windows DPAPI storage must hold an exclusive lifetime lease");

    storage->save(0, sample_credential());
    std::string encrypted;
    {
        std::ifstream ciphertext(fixture.path() / "orbit-storage.bin", std::ios::binary);
        encrypted.assign(std::istreambuf_iterator<char>(ciphertext), {});
    }
    require(!encrypted.empty() && encrypted.find(std::string(43, 's')) == std::string::npos,
            "Windows persisted file must contain only DPAPI ciphertext");
    storage.reset();
    storage = orbit::detail::open_storage(config);
    const auto reopened = storage->load();
    require(reopened.first == 0 && reopened.second &&
                (*reopened.second)["activation_id"].asString() ==
                    "synthetic_activation",
            "Windows DPAPI credentials must survive destroy and reopen");
    const auto data_path = (fixture.path() / L"orbit-storage.bin").wstring();
    HANDLE blocker = CreateFileW(data_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                 nullptr, OPEN_EXISTING,
                                 FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    require(blocker != INVALID_HANDLE_VALUE,
            "could not acquire synthetic no-delete-sharing file handle");
    bool failed_write = false;
    try {
        storage->save(0, sample_credential());
    } catch (const orbit::Error& error) {
        failed_write = error.kind() == orbit::ErrorKind::storage;
    }
    CloseHandle(blocker);
    bool poisoned = false;
    try {
        (void)storage->load();
    } catch (const orbit::Error& error) {
        poisoned = error.kind() == orbit::ErrorKind::storage;
    }
    require(failed_write && poisoned,
            "failed atomic replacement must poison the Windows storage instance");
    storage.reset();
    storage = orbit::detail::open_storage(config);
    require(storage->load().second &&
                (*storage->load().second)["activation_id"].asString() ==
                    "synthetic_activation",
            "a failed replacement must retain the previous DPAPI credential");
    require(storage->invalidate() == 1,
            "Windows invalidation must advance the persisted generation");
    storage.reset();
    storage = orbit::detail::open_storage(config);
    require(storage->version() == 1 && !storage->load().second,
            "Windows DPAPI tombstones must survive destroy and reopen");
    storage.reset();
    std::filesystem::remove(fixture.path() / "orbit-storage.bin");
    bool missing_rejected = false;
    try {
        (void)orbit::detail::open_storage(config);
    } catch (const orbit::Error& error) {
        missing_rejected = error.kind() == orbit::ErrorKind::storage;
    }
    require(missing_rejected, "a missing existing DPAPI record must never reset the scope");
}

#endif // _WIN32

} // namespace

int main() {
    try {
        test_installation_id_and_fingerprint_vectors();
        test_smbios_fixture_parser();
        test_native_clock();
        test_storage_codec_legacy_record_and_versions();
#if defined(__linux__)
        test_linux_secret_service_fake_helper_roundtrip();
        test_linux_helper_timeout_and_poisoned_pending_marker();
        test_linux_private_directory_and_lease_replacement();
#elif defined(_WIN32)
        test_windows_dpapi_storage_rename_name_lengths();
        test_windows_dpapi_storage_roundtrip_and_missing_state();
#endif
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "platform_test: " << error.what() << '\n';
        return 1;
    }
}
