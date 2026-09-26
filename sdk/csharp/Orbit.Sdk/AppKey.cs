using System.Text;

namespace Orbit.Sdk;

/// <summary>A parsed public key from Orbit's Integration page. It is not a secret.</summary>
public sealed class AppKey
{
    public string ApiOrigin { get; }
    public string Issuer => ApiOrigin;
    public string ApplicationId { get; }
    public string EnvironmentId { get; }
    public string Environment { get; }

    private AppKey(string apiOrigin, string applicationId, string environmentId, string environment)
    {
        ApiOrigin = apiOrigin;
        ApplicationId = applicationId;
        EnvironmentId = environmentId;
        Environment = environment;
    }

    public static AppKey Parse(string value) => ParseCore(value, allowLoopbackHttp: false);

    internal static AppKey ParseLocal(string value) => ParseCore(value, allowLoopbackHttp: true);

    private static AppKey ParseCore(string value, bool allowLoopbackHttp)
    {
        if (value == null) throw InvalidKey();
        var key = value.AsSpan().Trim();
        if (key.IsEmpty || key.Length > 512)
            throw InvalidKey();

        string environment;
        ReadOnlySpan<char> rest;
        if (key.StartsWith("orbit_app_test_", StringComparison.Ordinal))
        {
            environment = "test";
            rest = key["orbit_app_test_".Length..];
        }
        else if (key.StartsWith("orbit_app_live_", StringComparison.Ordinal))
        {
            environment = "live";
            rest = key["orbit_app_live_".Length..];
        }
        else
        {
            throw InvalidKey();
        }

        var firstDot = rest.IndexOf('.');
        if (firstDot <= 0)
            throw InvalidKey();
        var afterFirst = rest[(firstDot + 1)..];
        var secondOffset = afterFirst.IndexOf('.');
        if (secondOffset <= 0 || afterFirst[(secondOffset + 1)..].IndexOf('.') >= 0)
            throw InvalidKey();

        var encodedOrigin = rest[..firstDot];
        var application = afterFirst[..secondOffset];
        var environmentId = afterFirst[(secondOffset + 1)..];
        if (!Opaque(application) || !Opaque(environmentId))
            throw InvalidKey();

        string origin;
        try
        {
            var encoded = encodedOrigin.ToString();
            var bytes = JsonWire.DecodeBase64(encoded);
            origin = new UTF8Encoding(false, true).GetString(bytes);
            _ = Transport.ValidateOrigin(origin, allowLoopbackHttp);
            if (origin.EndsWith("/", StringComparison.Ordinal))
                throw InvalidKey();
        }
        catch (OrbitException)
        {
            throw InvalidKey();
        }
        catch (DecoderFallbackException)
        {
            throw InvalidKey();
        }
        return new AppKey(origin, application.ToString(), environmentId.ToString(), environment);
    }

    private static bool Opaque(ReadOnlySpan<char> value) => value.Length is >= 1 and <= 128 &&
        value.IndexOfAnyExcept("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") < 0;

    private static OrbitException InvalidKey() => new(OrbitError.Configuration, "invalid_app_key");
}

/// <summary>A caller supplied scoped device fingerprint. Raw machine identifiers are not accepted.</summary>
public sealed record Fingerprint(string Value, string Provider);

/// <summary>Optional installed-client settings. Machine binding uses machine_v1 by default.</summary>
public sealed record OrbitOptions
{
    public string? StatePath { get; init; }
    public bool DisableMachineBinding { get; init; }
    public Fingerprint? Fingerprint { get; init; }
}
