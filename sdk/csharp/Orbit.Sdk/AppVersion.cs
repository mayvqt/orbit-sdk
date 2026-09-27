using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Orbit.Sdk;

/// <summary>Application-version grammar, SDK identification and update hints.</summary>
internal static class AppVersion
{
    private const string Language = "csharp";

    internal static readonly string ClientHeader = CreateClientHeader();

    /// <summary>N[.N[.N[.N]]][-PRE][+BUILD] in at most 32 bytes.</summary>
    internal static bool Valid(string? value)
    {
        if (value is not { Length: >= 1 and <= 32 } || !value.All(char.IsAscii)) return false;
        var plus = value.IndexOf('+');
        var rest = plus < 0 ? value : value[..plus];
        var build = plus < 0 ? null : value[(plus + 1)..];
        var dash = rest.IndexOf('-');
        var core = dash < 0 ? rest : rest[..dash];
        var pre = dash < 0 ? null : rest[(dash + 1)..];
        var parts = core.Split('.');
        return parts.Length <= 4 && parts.All(Number) &&
               (pre == null || pre.Split('.').All(part => Identifier(part) && (!part.All(char.IsAsciiDigit) || Number(part)))) &&
               (build == null || build.Split('.').All(Identifier));
    }

    private static bool Number(string part) =>
        part.Length > 0 && part.All(char.IsAsciiDigit) && (part == "0" || part[0] != '0');

    private static bool Identifier(string part) =>
        part.Length > 0 && part.All(c => char.IsAsciiLetterOrDigit(c) || c == '-');

    internal static string? Configured(string? value) =>
        value == null || Valid(value) ? value : throw new OrbitException(OrbitError.Configuration, "invalid_app_version");

    internal static string? FormatClientHeader(string language, string sdkVersion, string platform)
    {
        var languageValid = language is { Length: >= 1 and <= 16 } && language[0] is >= 'a' and <= 'z' &&
            language.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');
        var platformValid = platform is { Length: >= 1 and <= 32 } && platform[0] is >= 'a' and <= 'z' or >= '0' and <= '9' &&
            platform.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '.' or '-');
        var header = $"{language}/{sdkVersion} ({platform})";
        return languageValid && platformValid && Valid(sdkVersion) && header.Length <= 128 ? header : null;
    }

    private static string CreateClientHeader()
    {
        var version = SdkVersion();
        return FormatClientHeader(Language, version, Platform()) ?? FormatClientHeader(Language, version, "unknown")!;
    }

    /// <summary>The package version from assembly metadata, without source-revision build metadata.</summary>
    internal static string SdkVersion()
    {
        var assembly = typeof(AppVersion).Assembly;
        var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (Valid(informational)) return informational!;
        var withoutBuild = informational?.Split('+')[0];
        if (Valid(withoutBuild)) return withoutBuild!;
        var version = assembly.GetName().Version;
        var numeric = version == null ? null : $"{version.Major}.{version.Minor}.{Math.Max(version.Build, 0)}";
        return Valid(numeric) ? numeric! : "0.0.0";
    }

    private static string Platform()
    {
        var os = OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsLinux() ? "linux" :
            OperatingSystem.IsMacOS() ? "macos" : OperatingSystem.IsFreeBSD() ? "freebsd" : "unknown";
        var arch = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x86_64",
            Architecture.Arm64 => "aarch64",
            Architecture.X86 => "x86",
            Architecture.Arm => "arm",
            var other => other.ToString().ToLowerInvariant()
        };
        var platform = new string($"{os}-{arch}".Select(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '.' or '-' ? c : '_').ToArray());
        return platform.Length > 32 ? platform[..32] : platform;
    }

    /// <summary>Returns the optional update_available version; a malformed hint invalidates the reply.</summary>
    internal static string? UpdateHint(JsonElement reply)
    {
        if (reply.ValueKind != JsonValueKind.Object || !reply.TryGetProperty("update_available", out var hint)) return null;
        if (hint.ValueKind != JsonValueKind.Object || !hint.TryGetProperty("version", out var version) ||
            version.ValueKind != JsonValueKind.String || version.GetString() is not { } text || !Valid(text))
            throw JsonWire.Invalid();
        return text;
    }
}
