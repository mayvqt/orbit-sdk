using System.Collections.ObjectModel;
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Orbit.Sdk;

internal static partial class JsonWire
{
    internal const int MaxBytes = 64 * 1024;
    internal static JsonElement Parse(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.Length > MaxBytes) throw Invalid();
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
            Unique(document.RootElement);
            return document.RootElement.Clone();
        }
        catch (JsonException) { throw Invalid(); }
    }
    private static void Unique(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw Invalid();
                Unique(property.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray()) Unique(item);
    }
    internal static JsonElement Field(JsonElement value, string name) =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var field) ? field : throw Invalid();
    internal static string String(JsonElement value, string name) => Text(Field(value, name));
    internal static string Text(JsonElement value) => value.ValueKind == JsonValueKind.String ? value.GetString()! : throw Invalid();
    internal static string? OptionalString(JsonElement value, string name)
    {
        if (!value.TryGetProperty(name, out var field) || field.ValueKind == JsonValueKind.Null) return null;
        return Text(field);
    }
    internal static long Integer(JsonElement value, string name)
    {
        var field = Field(value, name);
        return field.ValueKind == JsonValueKind.Number && field.TryGetInt64(out var result) ? result : throw Invalid();
    }
    internal static long? OptionalInteger(JsonElement value, string name) =>
        !value.TryGetProperty(name, out var field) || field.ValueKind == JsonValueKind.Null ? null : Integer(value, name);
    internal static bool Boolean(JsonElement value, string name) => Bool(Field(value, name));
    internal static bool Bool(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        _ => throw Invalid()
    };
    internal static void ExactFields(JsonElement value, params string[] fields)
    {
        if (value.ValueKind != JsonValueKind.Object) throw Invalid();
        var allowed = new HashSet<string>(fields, StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject()) if (!allowed.Remove(property.Name)) throw Invalid();
        if (allowed.Count != 0) throw Invalid();
    }
    internal static bool Opaque(string value) => value.Length is >= 1 and <= 128 &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-');
    internal static bool Bearer(string value) => value.Length == 43 && Opaque(value);
    internal static bool OperationId(string value) => value.Length is >= 16 and <= 128 && Opaque(value);
    internal static bool Feature(string value) => value.Length is >= 1 and <= 64 && value[0] is >= 'a' and <= 'z' &&
        value.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_');
    internal static IReadOnlyDictionary<string, bool> Entitlements(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object) throw Invalid();
        var result = new Dictionary<string, bool>(StringComparer.Ordinal);
        foreach (var item in value.EnumerateObject())
        {
            if (!Feature(item.Name) || result.Count == 64 || !result.TryAdd(item.Name, Bool(item.Value))) throw Invalid();
        }
        return new ReadOnlyDictionary<string, bool>(result);
    }
    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.0+)?(?:Z|[+-]\d{2}:\d{2})$", RegexOptions.CultureInvariant)]
    private static partial Regex TimestampPattern();
    internal static long Timestamp(string value)
    {
        if (value.Length > 64 || !TimestampPattern().IsMatch(value) ||
            !DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var result)) throw Invalid();
        return result.ToUnixTimeSeconds();
    }
    internal static string EncodeBase64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    internal static byte[] DecodeBase64(string value)
    {
        if (value.Length == 0 || !value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_')) throw Invalid();
        try
        {
            var bytes = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
            if (EncodeBase64(bytes) != value) throw Invalid();
            return bytes;
        }
        catch (FormatException) { throw Invalid(); }
    }
    internal static OrbitException Invalid() => new(OrbitError.InvalidResponse);
}
