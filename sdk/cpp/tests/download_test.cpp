#include "orbit_sdk.hpp"
#include "json.hpp"

#include <fstream>
#include <future>
#include <iostream>
#include <stdexcept>

namespace {
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }

std::string text(const Json::Value& value, const char* field) {
    require(value[field].isString(), "Missing fixture string");
    return value[field].asString();
}

template <typename Function>
void rejects(Function&& run, orbit::ErrorKind kind, std::string_view code) {
    bool rejected = false;
    try { run(); }
    catch (const orbit::Error& error) { rejected = error.kind() == kind && error.code() == code; }
    require(rejected, "Expected typed rejection");
}
} // namespace

int main() {
    using namespace orbit;
    using namespace orbit::detail;
    try {
        std::ifstream input(ORBIT_DOWNLOAD_VECTORS_PATH, std::ios::binary);
        require(input.good(), "Could not open shared download corpus");
        const std::string bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        const auto corpus = parse_json(bytes, 2 * 1024 * 1024);
        require(corpus["format_version"].asInt() == 1 && corpus["cases"].isArray() &&
            corpus["cases"].size() == 110, "Unexpected download corpus");
        std::size_t passed = 0;
        for (const auto& item : corpus["cases"]) {
            auto context = corpus["expected"];
            if (item.isMember("expected"))
                for (const auto& name : item["expected"].getMemberNames()) context[name] = item["expected"][name];
            bool accepted = false;
            try {
                const DownloadTicketVerifier verifier(text(context, "app_key"), text(context, "endpoint"),
                    encode_json(item.isMember("jwks") ? item["jwks"] : corpus["jwks"]));
                const auto now = Timestamp(std::chrono::seconds(json_int64(context["now"])));
                const auto ticket = verifier.verify(text(item, "token"), now);
                require(ticket.expires_at > now && ticket.byte_length > 0 && ticket.sha256.size() == 64,
                    "Invalid verified metadata");
                accepted = true;
            } catch (const Error& error) {
                if (error.kind() != ErrorKind::denied && error.kind() != ErrorKind::configuration) throw;
            }
            if (accepted != item["valid"].asBool())
                throw std::runtime_error("Download vector failed: " + text(item, "name"));
            ++passed;
        }
        auto app = text(corpus["expected"], "app_key");
        auto endpoint = text(corpus["expected"], "endpoint");
        auto encoded = encode_json(corpus["jwks"]);
        const auto token = text(corpus["cases"][0], "token");
        const auto now = Timestamp(std::chrono::seconds(json_int64(corpus["expected"]["now"])));
        const auto exact = encoded + std::string(16384 - encoded.size(), ' ');
        DownloadTicketVerifier verifier(app, endpoint, exact);
        require(verifier.verify(token, now).release_id == "release_1", "Exact key boundary rejected");
        for (const auto& malformed : {exact + " ", encoded.substr(0, encoded.size() - 1) + ",\"keys\":[]}"})
            rejects([&] { (void)DownloadTicketVerifier(app, endpoint, malformed); },
                ErrorKind::configuration, "invalid_download_keys");

        for (const auto* invalid_url : {"http://download.test/x", "https://user@download.test/x",
            "https://download.test:0/x", "https://download.test:000/x", "https://download.test:65536/x",
            "https://download.test:/x", "https://download.test/x?", "https://download.test/x#",
            "https://download.test/x\\y", "https://download.test/x%", "https://download.test/x%2g",
            "https://download.test/x{y}", "https://download.test/x y", "https://download.test/x\x7f"})
            rejects([&] { (void)DownloadTicketVerifier(app, invalid_url, encoded); },
                ErrorKind::configuration, "invalid_download_endpoint");
        for (const auto* valid_url : {"https://download.test", "https://download.test:65535/x%20y",
            "https://[::1]/x", "https://[::1]:443/x"})
            (void)DownloadTicketVerifier(app, valid_url, encoded);

        DownloadTicketVerifier owned(app, endpoint, encoded);
        app.clear(); endpoint.clear(); encoded.assign(encoded.size(), 'x');
        const auto copy = owned;
        const auto ticket = copy.verify(token, now);
        require(ticket.licence_id == "licence" && ticket.artifact_id == "artifact_1" &&
            ticket.ticket_id == "ticket_fixture_1" && ticket.byte_length == 1024 && ticket.issued_at == now &&
            ticket.expires_at == now + std::chrono::seconds(120), "Copied configuration or metadata changed");
        rejects([&] { (void)owned.verify(token, ticket.expires_at); }, ErrorKind::denied, "invalid_download_ticket");
        require(owned.verify(token, ticket.expires_at - std::chrono::seconds(1)).byte_length == 1024,
            "Ticket rejected before expiry");
        require(owned.verify(token, now - std::chrono::seconds(30)).byte_length == 1024, "Allowed skew rejected");
        rejects([&] { (void)owned.verify(token, now - std::chrono::seconds(31)); },
            ErrorKind::denied, "invalid_download_ticket");
        for (const auto invalid_now : {-1LL, 253402300800LL})
            rejects([&] { (void)owned.verify(token, Timestamp(std::chrono::seconds(invalid_now))); },
                ErrorKind::denied, "invalid_download_ticket");
        std::vector<std::future<DownloadTicket>> simultaneous;
        for (int i = 0; i < 32; ++i)
            simultaneous.push_back(std::async(std::launch::async, [owned, &token, now] { return owned.verify(token, now); }));
        for (auto& result : simultaneous) require(result.get().byte_length == 1024, "Concurrent verification failed");
        std::cout << "Shared download vectors: " << passed
            << " passed; key/endpoint boundaries, copied configuration, clock and concurrent checks pass.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
