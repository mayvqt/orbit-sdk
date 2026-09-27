#include "online.hpp"
#include "error.hpp"
#include <algorithm>

namespace orbit::detail {
std::string online_text(const Json::Value &value, const char *key) {
    if (!value.isObject() || !value.isMember(key) || !value[key].isString())
        raise(ErrorKind::invalid_response, "invalid_response");
    return value[key].asString();
}
std::int64_t online_number(const Json::Value &value, const char *key, std::int64_t minimum) {
    if (!value.isObject() || !value.isMember(key))
        raise(ErrorKind::invalid_response, "invalid_response");
    const auto number = json_int64(value[key]);
    if (number < minimum || number > max_safe_integer)
        raise(ErrorKind::invalid_response, "invalid_response");
    return number;
}
std::optional<Timestamp> online_time(const Json::Value &value, const char *key) {
    if (!value.isObject() || !value.isMember(key))
        raise(ErrorKind::invalid_response, "invalid_response");
    if (value[key].isNull())
        return std::nullopt;
    auto text = online_text(value, key);
    if (text.empty() || text.back() != 'Z')
        raise(ErrorKind::invalid_response, "invalid_response");
    // Public metadata timestamps use seconds. Validate, then floor finer RFC3339
    // precision.
    const auto dot = text.find('.');
    if (dot != std::string::npos) {
        if (dot != 19 || text.size() < 22 || text.size() > 30 ||
            !std::all_of(text.begin() + 20, text.end() - 1,
                         [](char c) { return c >= '0' && c <= '9'; }))
            raise(ErrorKind::invalid_response, "invalid_response");
        text = text.substr(0, dot) + "Z";
    }
    return Timestamp(std::chrono::seconds(online_timestamp(text)));
}
bool online_id(std::string_view value) {
    return !value.empty() && value.size() <= 128 &&
           std::all_of(value.begin(), value.end(), [](char c) {
               return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                      c == '_' || c == '-';
           });
}
Json::Value ClientState::online_operation(std::string_view route, Json::Value extra,
                                          const std::atomic_bool &cancelled) {
    ClientOperation call(*this);
    Credential saved;
    std::uint64_t expected;
    {
        std::lock_guard<std::mutex> lock(mutex);
        sync_storage_locked();
        throw_if_cancelled(cancelled);
        if (offline)
            raise(ErrorKind::denied, "online_activation_required");
        if (!credential)
            raise(ErrorKind::reauthentication_required, "reauthentication_required");
        saved = *credential;
        expected = current_generation;
    }
    auto body = credential_body(saved);
    for (const auto &key : extra.getMemberNames())
        body[key] = extra[key];
    try {
        auto reply = transport.post("/api/client/v1/activations/" + saved.activation_id + "/" +
                                        std::string(route),
                                    body, true, cancelled, 200);
        check_generation(expected, cancelled);
        if (!reply)
            raise(ErrorKind::invalid_response, "invalid_response");
        return *reply;
    } catch (...) {
        check_generation(expected, cancelled);
        throw;
    }
}
} // namespace orbit::detail

namespace orbit {
namespace {
using namespace detail;
void valid_name(std::string_view name) {
    if (name.empty() || name.size() > 64 || name.front() < 'a' || name.front() > 'z' ||
        !std::all_of(name.begin(), name.end(), [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        }))
        raise(ErrorKind::configuration, "configuration");
}
void units_valid(std::int64_t units) {
    if (units < 1 || units > max_safe_integer)
        raise(ErrorKind::configuration, "configuration");
}
std::string operation_id(std::optional<std::string_view> id) {
    if (id && (id->size() < 16 || !online_id(*id)))
        raise(ErrorKind::configuration, "configuration");
    return id ? std::string(*id) : new_installation_id();
}
ResourceCounter resource_counter(const Json::Value &v, std::string_view name) {
    ResourceCounter result{online_text(v, "name"), online_number(v, "limit"),
                           online_number(v, "used"), online_number(v, "remaining")};
    if (result.name != name || result.used > result.limit ||
        result.remaining != result.limit - result.used)
        raise(ErrorKind::invalid_response, "invalid_response");
    return result;
}
UsageCounter usage_counter(const Json::Value &v, std::string_view name) {
    UsageCounter result;
    static_cast<ResourceCounter &>(result) = resource_counter(v, name);
    auto period = online_text(v, "period");
    if (period == "day")
        result.period = UsagePeriod::day;
    else if (period == "month")
        result.period = UsagePeriod::month;
    else if (period == "lifetime")
        result.period = UsagePeriod::lifetime;
    else
        raise(ErrorKind::invalid_response, "invalid_response");
    result.period_started_at = online_time(v, "period_started_at");
    result.resets_at = online_time(v, "resets_at");
    if (result.period == UsagePeriod::lifetime ? (result.period_started_at || result.resets_at)
                                               : (!result.period_started_at || !result.resets_at ||
                                                  *result.period_started_at >= *result.resets_at))
        raise(ErrorKind::invalid_response, "invalid_response");
    return result;
}
ResourceAllocation allocation(const Json::Value &v, std::string_view name,
                              const std::string &operation) {
    ResourceAllocation result;
    result.counter = resource_counter(v, name);
    result.allocation_id = online_text(v, "allocation_id");
    result.resource_id = online_text(v, "resource_id");
    result.units = online_number(v, "units", 1);
    result.idempotency_key = online_text(v, "idempotency_key");
    auto state = online_text(v, "state");
    if (state == "active")
        result.state = AllocationState::active;
    else if (state == "released")
        result.state = AllocationState::released;
    else
        raise(ErrorKind::invalid_response, "invalid_response");
    if (!online_id(result.allocation_id) || !online_id(result.resource_id) ||
        result.idempotency_key != operation ||
        (result.state == AllocationState::active && result.units > result.counter.used))
        raise(ErrorKind::invalid_response, "invalid_response");
    return result;
}
[[noreturn]] void mutation_failure(const Error &error, const std::string &id, std::string_view name,
                                   std::int64_t units, bool resource) {
    std::optional<UsageCounter> usage;
    std::optional<ResourceCounter> capacity;
    if (error.code() == "usage_limit_reached" || error.code() == "resource_limit_reached") {
        try {
            const auto *wire = dynamic_cast<const WireError *>(&error);
            if (!wire || wire->status() != 409 || units == 0 ||
                error.code() != (resource ? "resource_limit_reached" : "usage_limit_reached") ||
                online_text(wire->detail, "idempotency_key") != id ||
                online_number(wire->detail, "requested_units", 1) != units)
                raise(ErrorKind::invalid_response, "invalid_response");
            if (resource)
                capacity = resource_counter(wire->detail["counter"], name);
            else
                usage = usage_counter(wire->detail["counter"], name);
            if (units <= (capacity ? capacity->remaining : usage->remaining))
                raise(ErrorKind::invalid_response, "invalid_response");
        } catch (const Error &) {
            throw OperationError(Error(1, ErrorKind::invalid_response, "invalid_response", {}), id);
        }
    }
    throw OperationError(error, id, usage, capacity,
                         usage || capacity ? std::optional<std::int64_t>(units) : std::nullopt);
}
class OnlineResultGuard {
  public:
    OnlineResultGuard(std::shared_ptr<ClientState> state, const Cancellation *cancellation)
        : state_(std::move(state)), cancellation_(cancellation) {
        if (!state_)
            raise(ErrorKind::configuration, "configuration");
        call_ = std::make_unique<ClientOperation>(*state_);
        generation_ = state_->generation();
    }
    template <class T> T finish(T result) const {
        if (state_->generation() != generation_)
            raise(ErrorKind::stale_response, "stale_response");
        std::atomic_bool inactive{false};
        check_cancelled(cancellation_flag(cancellation_, inactive).load() ||
                        state_->owner_cancelled->load());
        return result;
    }

  private:
    std::shared_ptr<ClientState> state_;
    const Cancellation *cancellation_;
    std::unique_ptr<ClientOperation> call_;
    std::uint64_t generation_ = 0;
};
Json::Value request(const std::shared_ptr<ClientState> &state, std::string_view path,
                    Json::Value body, const Cancellation *cancellation) {
    if (!state)
        raise(ErrorKind::configuration, "configuration");
    std::atomic_bool inactive{false};
    return state->online_operation(path, std::move(body),
                                   cancellation_flag(cancellation, inactive));
}
} // namespace
UsageCounter Client::usage(std::string_view name, const Cancellation *cancellation) const {
    valid_name(name);
    OnlineResultGuard guard(state_, cancellation);
    return guard.finish(usage_counter(
        request(state_, "usage/" + std::string(name), Json::Value(Json::objectValue), cancellation),
        name));
}
ResourceCounter Client::resources(std::string_view name, const Cancellation *cancellation) const {
    valid_name(name);
    OnlineResultGuard guard(state_, cancellation);
    return guard.finish(resource_counter(request(state_, "resources/" + std::string(name),
                                                 Json::Value(Json::objectValue), cancellation),
                                         name));
}
UsageConsumption Client::consume(std::string_view name, std::int64_t units,
                                 std::optional<std::string_view> idempotency_key,
                                 const Cancellation *cancellation) const {
    valid_name(name);
    units_valid(units);
    auto id = operation_id(idempotency_key);
    Json::Value body(Json::objectValue);
    body["units"] = Json::Int64(units);
    body["idempotency_key"] = id;
    try {
        OnlineResultGuard guard(state_, cancellation);
        auto reply = request(state_, "usage/" + std::string(name) + "/consume", body, cancellation);
        if (online_text(reply, "idempotency_key") != id ||
            online_number(reply, "consumed_units", 1) != units)
            raise(ErrorKind::invalid_response, "invalid_response");
        auto counter = usage_counter(reply, name);
        if (counter.used < units)
            raise(ErrorKind::invalid_response, "invalid_response");
        return guard.finish(UsageConsumption{counter, id, units});
    } catch (const Error &e) {
        mutation_failure(e, id, name, units, false);
    }
}
ResourceAllocation Client::acquire_resource(std::string_view name, std::string_view resource_id,
                                            std::int64_t units,
                                            std::optional<std::string_view> idempotency_key,
                                            const Cancellation *cancellation) const {
    valid_name(name);
    units_valid(units);
    if (!online_id(resource_id))
        raise(ErrorKind::configuration, "configuration");
    auto id = operation_id(idempotency_key);
    Json::Value body(Json::objectValue);
    body["units"] = Json::Int64(units);
    body["resource_id"] = std::string(resource_id);
    body["idempotency_key"] = id;
    try {
        OnlineResultGuard guard(state_, cancellation);
        auto reply = allocation(
            request(state_, "resources/" + std::string(name) + "/acquire", body, cancellation),
            name, id);
        if (reply.resource_id != resource_id || reply.units != units)
            raise(ErrorKind::invalid_response, "invalid_response");
        return guard.finish(std::move(reply));
    } catch (const Error &e) {
        mutation_failure(e, id, name, units, true);
    }
}
ResourceAllocation Client::release_resource(std::string_view name, std::string_view allocation_id,
                                            std::optional<std::string_view> idempotency_key,
                                            const Cancellation *cancellation) const {
    valid_name(name);
    if (!online_id(allocation_id))
        raise(ErrorKind::configuration, "configuration");
    auto id = operation_id(idempotency_key);
    Json::Value body(Json::objectValue);
    body["idempotency_key"] = id;
    try {
        OnlineResultGuard guard(state_, cancellation);
        auto reply = allocation(request(state_,
                                        "resources/" + std::string(name) + "/allocations/" +
                                            std::string(allocation_id) + "/release",
                                        body, cancellation),
                                name, id);
        if (reply.allocation_id != allocation_id || reply.state != AllocationState::released)
            raise(ErrorKind::invalid_response, "invalid_response");
        return guard.finish(std::move(reply));
    } catch (const Error &e) {
        mutation_failure(e, id, name, 0, true);
    }
}
} // namespace orbit

namespace orbit::detail {
namespace {
bool target_label(std::string_view value) {
    return !value.empty() && value.size() <= 32 && value.front() >= 'a' && value.front() <= 'z' &&
           std::all_of(value.begin(), value.end(), [](char c) {
               return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
           });
}
void exact(const Json::Value &value, std::initializer_list<const char *> fields) {
    if (!value.isObject() || value.size() != fields.size())
        raise(ErrorKind::invalid_response, "invalid_response");
    for (const auto *field : fields)
        if (!value.isMember(field))
            raise(ErrorKind::invalid_response, "invalid_response");
}
ReleaseArtifact artifact_result(const Json::Value &v) {
    exact(v, {"id", "release_id", "platform", "architecture", "filename", "byte_length", "sha256",
              "delivery_mode", "url", "required_feature"});
    ReleaseArtifact a;
    a.id = online_text(v, "id");
    a.release_id = online_text(v, "release_id");
    a.target = {online_text(v, "platform"), online_text(v, "architecture")};
    a.filename = online_text(v, "filename");
    a.byte_length = online_number(v, "byte_length", 1);
    a.sha256 = online_text(v, "sha256");
    a.url = online_text(v, "url");
    const auto mode = online_text(v, "delivery_mode");
    if (mode == "public")
        a.delivery_mode = DeliveryMode::public_url;
    else if (mode == "protected")
        a.delivery_mode = DeliveryMode::protected_endpoint;
    else
        raise(ErrorKind::invalid_response, "invalid_response");
    if (!v["required_feature"].isNull())
        a.required_feature = online_text(v, "required_feature");
    validate_artifact(a);
    return a;
}
} // namespace
void validate_artifact(const ReleaseArtifact &a) {
    if (!online_id(a.id) || !online_id(a.release_id) || !target_label(a.target.platform) ||
        !target_label(a.target.architecture) || a.byte_length < 1 ||
        a.byte_length > max_safe_integer || a.sha256.size() != 64 ||
        !std::all_of(a.sha256.begin(), a.sha256.end(),
                     [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }) ||
        a.filename.empty() || a.filename.size() > 255 || a.filename == "." || a.filename == ".." ||
        std::any_of(a.filename.begin(), a.filename.end(),
                    [](unsigned char c) { return c < 32 || c == 127 || c == '/' || c == '\\'; }) ||
        (a.delivery_mode != DeliveryMode::public_url &&
         a.delivery_mode != DeliveryMode::protected_endpoint))
        raise(ErrorKind::invalid_response, "invalid_response");
    if (a.required_feature) {
        try {
            valid_name(*a.required_feature);
        } catch (const Error &) {
            raise(ErrorKind::invalid_response, "invalid_response");
        }
    }
    try {
        validate_delivery_url(a.url, a.delivery_mode == DeliveryMode::public_url);
    } catch (const Error &) {
        raise(ErrorKind::invalid_response, "invalid_response");
    }
}
void validate_authorization(const DownloadAuthorization &a) {
    validate_artifact(a.artifact);
    if (a.artifact.delivery_mode == DeliveryMode::public_url) {
        if (a.ticket || a.expires_at)
            raise(ErrorKind::invalid_response, "invalid_response");
    } else if (!a.expires_at || !a.ticket || a.ticket->empty() || a.ticket->size() > 16384 ||
               std::count(a.ticket->begin(), a.ticket->end(), '.') != 2 ||
               !std::all_of(a.ticket->begin(), a.ticket->end(), [](char c) {
                   return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                          (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
               }))
        raise(ErrorKind::invalid_response, "invalid_response");
}
} // namespace orbit::detail

namespace orbit {
UpdateTarget UpdateTarget::runtime() {
    UpdateTarget result;
#if defined(_WIN32)
    result.platform = "windows";
#elif defined(__APPLE__)
    result.platform = "macos";
#elif defined(__linux__)
    result.platform = "linux";
#else
    detail::raise(ErrorKind::configuration, "explicit_target_required");
#endif
#if defined(__x86_64__) || defined(_M_X64)
    result.architecture = "x64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    result.architecture = "arm64";
#elif defined(__i386__) || defined(_M_IX86)
    result.architecture = "x86";
#elif defined(__ARM_ARCH) && __ARM_ARCH == 7
    result.architecture = "armv7";
#else
    detail::raise(ErrorKind::configuration, "explicit_target_required");
#endif
    return result;
}
std::optional<AvailableUpdate> Client::check_for_update(std::int64_t installed_release_number,
                                                        std::string_view channel,
                                                        std::optional<UpdateTarget> target,
                                                        const Cancellation *cancellation) const {
    using namespace detail;
    if (!target)
        target = UpdateTarget::runtime();
    if (installed_release_number < 0 || installed_release_number > max_safe_integer ||
        !target_label(channel) || !target_label(target->platform) ||
        !target_label(target->architecture))
        raise(ErrorKind::configuration, "configuration");
    Json::Value body(Json::objectValue);
    body["installed_release_number"] = Json::Int64(installed_release_number);
    body["channel"] = std::string(channel);
    body["platform"] = target->platform;
    body["architecture"] = target->architecture;
    OnlineResultGuard guard(state_, cancellation);
    auto v = request(state_, "updates", body, cancellation);
    exact(v, {"release", "artifact"});
    if (v["release"].isNull() && v["artifact"].isNull())
        return guard.finish(std::optional<AvailableUpdate>{});
    auto a = artifact_result(v["artifact"]);
    const auto &r = v["release"];
    exact(r, {"id", "channel", "version", "notes", "release_number", "state", "created_at",
              "published_at", "artifacts"});
    if (!r["artifacts"].isArray() || r["artifacts"].size() != 1 ||
        r["artifacts"][0] != v["artifact"] || a.target.platform != target->platform ||
        a.target.architecture != target->architecture || online_text(r, "id") != a.release_id ||
        online_text(r, "channel") != channel || online_text(r, "state") != "published")
        raise(ErrorKind::invalid_response, "invalid_response");
    Release release;
    release.id = a.release_id;
    release.channel = std::string(channel);
    release.version = online_text(r, "version");
    release.notes = online_text(r, "notes");
    release.release_number = online_number(r, "release_number", 1);
    const auto created = online_time(r, "created_at"), published = online_time(r, "published_at");
    if (!created || !published || release.release_number <= installed_release_number ||
        release.version.empty() || release.version.size() > 64 || release.notes.size() > 8192 ||
        std::any_of(release.version.begin(), release.version.end(),
                    [](unsigned char c) { return c < 32 || c == 127; }))
        raise(ErrorKind::invalid_response, "invalid_response");
    release.created_at = *created;
    release.published_at = *published;
    release.artifacts = {a};
    return guard.finish(AvailableUpdate{std::move(release), std::move(a)});
}
DownloadAuthorization Client::authorize_download(std::string_view release_id,
                                                 std::string_view artifact_id,
                                                 const Cancellation *cancellation) const {
    using namespace detail;
    if (!online_id(release_id) || !online_id(artifact_id))
        raise(ErrorKind::configuration, "configuration");
    Json::Value body(Json::objectValue);
    body["release_id"] = std::string(release_id);
    body["artifact_id"] = std::string(artifact_id);
    OnlineResultGuard guard(state_, cancellation);
    auto v = request(state_, "downloads/authorize", body, cancellation);
    exact(v, {"artifact", "ticket", "expires_at"});
    DownloadAuthorization result;
    result.artifact = artifact_result(v["artifact"]);
    if (result.artifact.id != artifact_id || result.artifact.release_id != release_id)
        raise(ErrorKind::invalid_response, "invalid_response");
    if (!v["ticket"].isNull())
        result.ticket = online_text(v, "ticket");
    result.expires_at = online_time(v, "expires_at");
    validate_authorization(result);
    return guard.finish(std::move(result));
}
void DownloadAuthorization::download(std::string_view destination, std::int64_t maximum_bytes,
                                     bool replace, const Cancellation *cancellation) const {
    std::atomic_bool inactive{false};
    detail::download_stream(*this, destination, maximum_bytes, replace,
                            detail::cancellation_flag(cancellation, inactive));
}
} // namespace orbit

namespace orbit::detail {
namespace {
std::optional<std::string> required_feature(const Json::Value &value) {
    if (!value.isObject() || !value.isMember("required_feature"))
        raise(ErrorKind::invalid_response, "invalid_response");
    if (value["required_feature"].isNull())
        return std::nullopt;
    auto feature = online_text(value, "required_feature");
    try {
        valid_name(feature);
    } catch (const Error &) {
        raise(ErrorKind::invalid_response, "invalid_response");
    }
    return feature;
}
template <class T, class Parser>
std::map<std::string, T> definitions(const Json::Value &value, const char *field, Parser parse) {
    std::map<std::string, T> result;
    if (!value.isObject() || !value.isMember(field))
        raise(ErrorKind::invalid_response, "invalid_response");
    const auto &entries = value[field];
    if (!entries.isObject() || entries.size() > 32)
        raise(ErrorKind::invalid_response, "invalid_response");
    for (const auto &name : entries.getMemberNames()) {
        try {
            valid_name(name);
        } catch (const Error &) {
            raise(ErrorKind::invalid_response, "invalid_response");
        }
        result.emplace(name, parse(entries[name]));
    }
    return result;
}
} // namespace
std::map<std::string, UsageLimit> usage_definitions(const Json::Value &value) {
    return definitions<UsageLimit>(value, "usage_limits", [](const Json::Value &entry) {
        exact(entry, {"limit", "period", "required_feature"});
        auto period = online_text(entry, "period");
        UsagePeriod parsed;
        if (period == "day")
            parsed = UsagePeriod::day;
        else if (period == "month")
            parsed = UsagePeriod::month;
        else if (period == "lifetime")
            parsed = UsagePeriod::lifetime;
        else
            raise(ErrorKind::invalid_response, "invalid_response");
        return UsageLimit{online_number(entry, "limit"), parsed, required_feature(entry)};
    });
}
std::map<std::string, ResourceLimit> resource_definitions(const Json::Value &value) {
    return definitions<ResourceLimit>(value, "resource_limits", [](const Json::Value &entry) {
        exact(entry, {"limit", "required_feature"});
        return ResourceLimit{online_number(entry, "limit"), required_feature(entry)};
    });
}
} // namespace orbit::detail
