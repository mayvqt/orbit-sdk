#pragma once
#include "core.hpp"
namespace orbit::detail {
std::int64_t online_timestamp(std::string_view value);
constexpr std::int64_t max_safe_integer = 9007199254740991LL;
std::map<std::string, UsageLimit> usage_definitions(const Json::Value &value);
std::map<std::string, ResourceLimit> resource_definitions(const Json::Value &value);
std::string online_text(const Json::Value &value, const char *key);
std::int64_t online_number(const Json::Value &value, const char *key, std::int64_t minimum = 0);
std::optional<Timestamp> online_time(const Json::Value &value, const char *key);
void validate_delivery_url(std::string_view url, bool allow_query);
void validate_artifact(const ReleaseArtifact &artifact);
void validate_authorization(const DownloadAuthorization &authorization);
void download_stream(const DownloadAuthorization &authorization, std::string_view destination,
                     std::int64_t maximum_bytes, bool replace, const std::atomic_bool &cancelled,
                     std::string_view test_ca = {});
bool online_id(std::string_view value);
} // namespace orbit::detail
