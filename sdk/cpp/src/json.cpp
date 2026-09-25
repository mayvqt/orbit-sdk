#include "json.hpp"

#include "error.hpp"

#include <json/writer.h>

#include <cmath>

namespace orbit::detail {
namespace {

bool valid_utf8(std::string_view text) {
    std::size_t i = 0;
    while (i < text.size()) {
        const auto c = static_cast<unsigned char>(text[i]);
        if (c <= 0x7f) {
            ++i;
            continue;
        }
        std::size_t count = 0;
        std::uint32_t value = 0;
        if ((c & 0xe0) == 0xc0) {
            count = 2;
            value = c & 0x1f;
            if (value < 2) return false;
        } else if ((c & 0xf0) == 0xe0) {
            count = 3;
            value = c & 0x0f;
        } else if ((c & 0xf8) == 0xf0) {
            count = 4;
            value = c & 0x07;
            if (value > 4) return false;
        } else {
            return false;
        }
        if (i + count > text.size()) return false;
        for (std::size_t j = 1; j < count; ++j) {
            const auto next = static_cast<unsigned char>(text[i + j]);
            if ((next & 0xc0) != 0x80) return false;
            value = (value << 6) | (next & 0x3f);
        }
        if ((count == 3 && value < 0x800) || (count == 4 && value < 0x10000) ||
            value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) {
            return false;
        }
        i += count;
    }
    return true;
}

void configure_reader(Json::CharReaderBuilder& builder, bool reject_duplicates) {
    builder["allowComments"] = false;
    builder["allowTrailingCommas"] = false;
    builder["strictRoot"] = true;
    builder["allowDroppedNullPlaceholders"] = false;
    builder["allowNumericKeys"] = false;
    builder["allowSingleQuotes"] = false;
    builder["failIfExtra"] = true;
    builder["rejectDupKeys"] = reject_duplicates;
    builder["allowSpecialFloats"] = false;
    builder["stackLimit"] = 64;
}

bool valid_decoded_json(const Json::Value& value) {
    if (value.isString()) {
        return valid_utf8(value.asString());
    }
    if (value.type() == Json::realValue && !std::isfinite(value.asDouble())) {
        return false;
    }
    if (value.isArray()) {
        for (const auto& item : value) {
            if (!valid_decoded_json(item)) return false;
        }
    } else if (value.isObject()) {
        for (auto it = value.begin(); it != value.end(); ++it) {
            if (!valid_utf8(it.name()) || !valid_decoded_json(*it)) return false;
        }
    }
    return true;
}

bool parse_with_duplicate_policy(std::string_view input, std::size_t limit,
                                 bool reject_duplicates, Json::Value& result) {
    if (input.size() > limit || !valid_utf8(input)) return false;
    Json::CharReaderBuilder builder;
    configure_reader(builder, reject_duplicates);
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    std::string errors;
    return reader->parse(input.data(), input.data() + input.size(), &result, &errors);
}

} // namespace

Json::Value parse_json(std::string_view input, std::size_t limit) {
    Json::Value result;
    if (!parse_with_duplicate_policy(input, limit, true, result) ||
        !valid_decoded_json(result)) {
        raise(ErrorKind::invalid_response, "invalid_json");
    }
    return result;
}

bool json_has_top_level_member(std::string_view input, std::string_view member,
                               std::size_t limit) {
    Json::Value result;
    return parse_with_duplicate_policy(input, limit, false, result) &&
           result.isObject() && result.isMember(std::string(member));
}

std::string encode_json(const Json::Value& value) {
    Json::StreamWriterBuilder builder;
    builder["commentStyle"] = "None";
    builder["indentation"] = "";
    builder["emitUTF8"] = true;
    builder["precision"] = 17;
    builder["precisionType"] = "significant";
    return Json::writeString(builder, value);
}

std::int64_t json_int64(const Json::Value& value) {
    if ((value.type() != Json::intValue && value.type() != Json::uintValue) || !value.isInt64()) {
        raise(ErrorKind::invalid_response, "invalid_response");
    }
    return value.asInt64();
}

} // namespace orbit::detail
