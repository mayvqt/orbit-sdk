using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Orbit.Sdk;

// Private binary format: fixed fields, strict UTF-8, no optional/unknown tail.
// This never changes StoredCredential's public serialization protections.
internal static class ProtectedStorageCodec
{
    internal const int MaximumPlaintext = WindowsDataProtection.MaxPlaintextBytes;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static ReadOnlySpan<byte> Magic => "Orbit.CSharp.Storage\0"u8;

    internal static byte[] Entropy(OrbitConfig config, Device device)
    {
        try
        {
            config.Validate(device);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            hash.AppendData("orbit.sdk.storage.v1\0"u8);
            Span<byte> length = stackalloc byte[4];
            foreach (var value in new[] { config.Issuer, config.ApplicationId, config.EnvironmentId, device.InstallationId })
            {
                var bytes = Utf8.GetBytes(value);
                BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)bytes.Length));
                hash.AppendData(length);
                hash.AppendData(bytes);
            }
            return hash.GetHashAndReset();
        }
        catch (Exception) { throw Storage(); }
    }

    internal static byte[] Encode(long version, StoredCredential? credential, OrbitConfig config, Device device)
    {
        var buffer = new byte[MaximumPlaintext];
        try
        {
            config.Validate(device);
            if (version < 0) throw Storage();
            if (credential != null) ValidateCredential(credential, config, device);
            var writer = new Writer(buffer);
            writer.Bytes(Magic);
            writer.Integer(1);
            writer.Integer(version);
            writer.Bytes(Entropy(config, device));
            // Bind fingerprint metadata even in a tombstone, so a different
            // binding cannot silently reuse an otherwise identical scope.
            writer.OptionalText(device.Fingerprint);
            writer.OptionalText(device.FingerprintProvider);
            writer.Byte(credential == null ? (byte)0 : (byte)1);
            if (credential != null)
            {
                writer.Text(credential.ActivationId);
                writer.Text(credential.LicenceId);
                writer.Text(credential.Credential);
                writer.Integer(credential.CredentialExpiresAt);
            }
            return buffer.AsSpan(0, writer.Length).ToArray();
        }
        catch (Exception) { throw Storage(); }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    internal static (long Version, StoredCredential? Credential) Decode(ReadOnlySpan<byte> plaintext, OrbitConfig config, Device device)
    {
        try
        {
            config.Validate(device);
            if (plaintext.Length is 0 or > MaximumPlaintext) throw Storage();
            var reader = new Reader(plaintext);
            if (!reader.Bytes(Magic.Length).SequenceEqual(Magic) || reader.Integer() != 1) throw Storage();
            var version = reader.Integer();
            if (version < 0 || !CryptographicOperations.FixedTimeEquals(reader.Bytes(32), Entropy(config, device)) ||
                reader.OptionalText(64) != device.Fingerprint || reader.OptionalText(55) != device.FingerprintProvider)
                throw Storage();
            var present = reader.Byte();
            StoredCredential? credential = present switch
            {
                0 => null,
                1 => new StoredCredential
                {
                    ApplicationId = config.ApplicationId, EnvironmentId = config.EnvironmentId,
                    InstallationId = device.InstallationId, Fingerprint = device.Fingerprint,
                    FingerprintProvider = device.FingerprintProvider,
                    ActivationId = reader.Text(128), LicenceId = reader.Text(128),
                    Credential = reader.Text(43), CredentialExpiresAt = reader.Integer()
                },
                _ => throw Storage()
            };
            if (!reader.Finished) throw Storage();
            if (credential != null) ValidateCredential(credential, config, device);
            return (version, credential);
        }
        catch (Exception) { throw Storage(); }
    }

    private static void ValidateCredential(StoredCredential value, OrbitConfig config, Device device)
    {
        if (value.ApplicationId != config.ApplicationId || value.EnvironmentId != config.EnvironmentId ||
            value.InstallationId != device.InstallationId || value.Fingerprint != device.Fingerprint ||
            value.FingerprintProvider != device.FingerprintProvider || !JsonWire.Opaque(value.ActivationId) ||
            !JsonWire.Opaque(value.LicenceId) || !JsonWire.Bearer(value.Credential) || value.CredentialExpiresAt < 0)
            throw Storage();
    }

    private ref struct Writer(Span<byte> buffer)
    {
        private Span<byte> buffer = buffer;
        internal int Length { get; private set; }
        internal void Bytes(ReadOnlySpan<byte> value) { value.CopyTo(buffer[Length..]); Length += value.Length; }
        internal void Byte(byte value) { buffer[Length++] = value; }
        internal void Integer(long value) { BinaryPrimitives.WriteInt64BigEndian(buffer[Length..], value); Length += 8; }
        internal void OptionalText(string? value) { Byte(value == null ? (byte)0 : (byte)1); if (value != null) Text(value); }
        internal void Text(string value)
        {
            var size = Utf8.GetByteCount(value);
            BinaryPrimitives.WriteUInt32BigEndian(buffer[Length..], checked((uint)size));
            Length += 4;
            Length += Utf8.GetBytes(value, buffer[Length..]);
        }
    }

    private ref struct Reader(ReadOnlySpan<byte> buffer)
    {
        private ReadOnlySpan<byte> remaining = buffer;
        internal bool Finished => remaining.IsEmpty;
        internal ReadOnlySpan<byte> Bytes(int count) { var value = remaining[..count]; remaining = remaining[count..]; return value; }
        internal byte Byte() => Bytes(1)[0];
        internal long Integer() => BinaryPrimitives.ReadInt64BigEndian(Bytes(8));
        internal string? OptionalText(int maximum) => Byte() switch { 0 => null, 1 => Text(maximum), _ => throw Storage() };
        internal string Text(int maximum)
        {
            var length = BinaryPrimitives.ReadUInt32BigEndian(Bytes(4));
            if (length is 0 || length > maximum) throw Storage();
            return Utf8.GetString(Bytes((int)length));
        }
    }

    private static OrbitException Storage() => new(OrbitError.Storage);
}
