#include "offline.hpp"

#include <fstream>
#include <iostream>
#include <stdexcept>

namespace {
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }

std::string text(const Json::Value& value, const char* field) {
    require(value[field].isString(), "Missing fixture string");
    return value[field].asString();
}
} // namespace

int main() {
    using namespace orbit;
    using namespace orbit::detail;
    try {
        std::ifstream input(ORBIT_OFFLINE_VECTORS_PATH, std::ios::binary);
        require(input.good(), "Could not open shared offline corpus");
        const std::string bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        const auto corpus = parse_json(bytes, 2 * 1024 * 1024);
        require(corpus["format_version"].asInt() == 1 && corpus["cases"].isArray() &&
            corpus["cases"].size() == 104, "Unexpected offline corpus");
        std::size_t passed = 0;
        for (const auto& item : corpus["cases"]) {
            auto context = corpus["expected"];
            if (item.isMember("expected"))
                for (const auto& name : item["expected"].getMemberNames()) context[name] = item["expected"][name];
            bool accepted = false;
            try {
                auto app = AppKey::parse(text(context, "app_key"));
                std::optional<Fingerprint> fingerprint;
                if (!context["fingerprint"].isNull())
                    fingerprint = Fingerprint{text(context, "fingerprint"), text(context, "fingerprint_provider")};
                OfflineExpected expected{app, text(context, "installation_id"), std::move(fingerprint),
                    json_int64(context["now"]), json_int64(context["minimum_sequence"])};
                const auto keys = OfflineKeys::parse(item.isMember("jwks") ? item["jwks"] : corpus["jwks"], app.environment());
                const auto file = keys.verify(text(item, "token"), expected);
                require(file.expires_at > expected.now && file.entitlements.at("export"), "Invalid verified metadata");
                if (text(item, "name") == "valid_six_month_term")
                    require(file.content_digest == "8aed1c86dab86f56c744802ee68650041ddc12e8d56bb6d73c2f40049424740a",
                        "Canonical claim digest differs from Python and C#");
                accepted = true;
            } catch (const Error& error) {
                if (error.kind() != ErrorKind::invalid_response) throw;
            }
            if (accepted != item["valid"].asBool())
                throw std::runtime_error("Offline vector failed: " + text(item, "name"));
            ++passed;
        }
        const auto encoded = encode_json(corpus["jwks"]);
        const auto exact = encoded + std::string(16384 - encoded.size(), ' ');
        require(OfflineKeys::parse_jwks(exact, "test").verify(text(corpus["cases"][0], "token"),
            OfflineExpected{AppKey::parse(text(corpus["expected"], "app_key")),
                text(corpus["expected"], "installation_id"), std::nullopt,
                json_int64(corpus["expected"]["now"])}).sequence == 1, "Exact key boundary rejected");
        for (const auto& malformed : {exact + " ", encoded.substr(0, encoded.size() - 1) + ",\"keys\":[]}"}) {
            bool rejected = false;
            try { (void)OfflineKeys::parse_jwks(malformed, "test"); }
            catch (const Error& error) { rejected = error.kind() == ErrorKind::invalid_response; }
            require(rejected, "Oversized or duplicate-key JWKS accepted");
        }
        std::cout << "Shared offline vectors: " << passed << " passed; canonical digest and strict key boundaries pass.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
