using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Orbit.Sdk;

internal static class DownloadStreamTests
{
    internal static async Task<int> RunAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "orbit-download-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            await using var fixture = new TlsFixture();
            var path = Path.Combine(directory, "artifact.bin");
            DownloadAuthorization Authorization(string route, bool protect = false) => new(new("artifact", "release",
                new("linux", "x64"), "ignored.bin", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                protect ? DeliveryMode.Protected : DeliveryMode.Public, fixture.Origin + route, null),
                protect ? "e30.e30.c2ln" : null, protect ? DateTimeOffset.UtcNow.AddSeconds(120) : null);
            await Failure(() => Authorization("/bytes").DownloadAsync(path, 3));
            Require(!File.Exists(path));
            ArtifactDownload.TestHandler = () => new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                UseProxy = false,
                SslOptions = new SslClientAuthenticationOptions
                {
                    RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                    {
                        if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0 || certificate == null) return false;
                        using var chain = new X509Chain();
                        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                        chain.ChainPolicy.CustomTrustStore.Add(fixture.Certificate);
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        return chain.Build(new X509Certificate2(certificate));
                    }
                }
            };
            await Authorization("/redirect/5", true).DownloadAsync(path, 3);
            Require(await File.ReadAllTextAsync(path) == "abc");
            Require(fixture.Requests["/redirect/5"].Authorization == "Bearer e30.e30.c2ln");
            foreach (var request in fixture.Requests.Where(pair => pair.Key != "/redirect/5"))
                Require(request.Value.Authorization == "" && request.Value.Cookie == "" && request.Value.Encoding == "identity");
            await Failure(() => Authorization("/bytes").DownloadAsync(path, 3));
            foreach (var route in new[] { "/redirect/6", "/downgrade", "/encoded", "/length", "/oversize", "/short", "/wrong" })
            {
                await Failure(() => Authorization(route).DownloadAsync(path, 3, replace: true));
                Require(await File.ReadAllTextAsync(path) == "abc");
                Require(Directory.GetFiles(directory).Length == 1);
            }
            using var cancellation = new CancellationTokenSource();
            var pending = Authorization("/slow").DownloadAsync(path, 3, replace: true, cancellationToken: cancellation.Token);
            await fixture.Slow.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancellation.Cancel();
            await Failure(() => pending, OrbitError.Cancelled);
            Require(await File.ReadAllTextAsync(path) == "abc" && Directory.GetFiles(directory).Length == 1);
            ArtifactDownload.TestTimeout = TimeSpan.FromMilliseconds(200);
            await Failure(() => Authorization("/slow").DownloadAsync(path, 3, replace: true)
                .WaitAsync(TimeSpan.FromSeconds(3)), OrbitError.Transient);
            Require(await File.ReadAllTextAsync(path) == "abc" && Directory.GetFiles(directory).Length == 1);
            ArtifactDownload.TestTimeout = null;
            await Authorization("/bytes").DownloadAsync(path, 3, replace: true);
            Console.WriteLine("Direct download TLS: trust, five redirects, bearer/cookie stripping, identity, limits, hash, atomic replacement, cancellation and stalled-body timeout passed.");
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine($"Direct download TLS failed: {e.GetType().Name}: {e.Message}"); return 1; }
        finally { ArtifactDownload.TestHandler = null; ArtifactDownload.TestTimeout = null; Directory.Delete(directory, recursive: true); }
    }
    private static void Require(bool condition) { if (!condition) throw new InvalidOperationException("download regression"); }
    private static async Task Failure(Func<Task> call, OrbitError? expected = null)
    {
        try { await call(); }
        catch (OrbitException e) { if (expected != null) Require(e.Error == expected); return; }
        throw new InvalidOperationException("invalid download accepted");
    }
    private sealed class TlsFixture : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource stop = new();
        private readonly Task serving;
        internal readonly System.Collections.Concurrent.ConcurrentDictionary<string, (string Authorization, string Cookie, string Encoding)> Requests = new();
        internal readonly TaskCompletionSource Slow = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal X509Certificate2 Certificate { get; }
        internal string Origin { get; }
        internal TlsFixture()
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=127.0.0.1", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var names = new SubjectAlternativeNameBuilder(); names.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(names.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            Certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
            listener.Start(); Origin = $"https://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}";
            serving = Serve();
        }
        private async Task Serve()
        {
            var tasks = new List<Task>();
            try { while (!stop.IsCancellationRequested) tasks.Add(Connection(await listener.AcceptTcpClientAsync(stop.Token))); }
            catch (OperationCanceledException) { }
            finally { await Task.WhenAll(tasks); }
        }
        private async Task Connection(TcpClient connection)
        {
            using (connection)
            await using (var stream = new SslStream(connection.GetStream()))
            {
                try
                {
                    await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = Certificate }, stop.Token);
                    using var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, leaveOpen: true);
                    var first = await reader.ReadLineAsync(stop.Token);
                    if (first == null) return;
                    var route = first.Split(' ')[1];
                    var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    string? line;
                    while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync(stop.Token)))
                    { var colon = line.IndexOf(':'); headers[line[..colon]] = line[(colon + 1)..].Trim(); }
                    Requests[route] = (headers.GetValueOrDefault("Authorization", ""), headers.GetValueOrDefault("Cookie", ""), headers.GetValueOrDefault("Accept-Encoding", ""));
                    var status = 200;
                    var extra = "";
                    var bytes = "abc";
                    if (route.StartsWith("/redirect/"))
                    {
                        var remaining = int.Parse(route.Split('/')[2]); status = 302; bytes = "";
                        extra = "Location: " + (remaining == 1 ? "/bytes" : $"/redirect/{remaining - 1}") + "\r\nSet-Cookie: secret=fixture\r\n";
                    }
                    if (route == "/downgrade") { status = 302; extra = "Location: http://127.0.0.1/bytes\r\n"; }
                    if (route == "/encoded") extra += "Content-Encoding: gzip\r\n";
                    if (route == "/length") extra += "Content-Length: 4\r\n";
                    if (route == "/short") extra += "Content-Length: 3\r\n";
                    if (route == "/short") bytes = "ab";
                    if (route == "/wrong") bytes = "xyz";
                    if (route == "/oversize") bytes = "abcd";
                    var response = $"HTTP/1.1 {status} Fixture\r\nConnection: close\r\n{extra}\r\n";
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(response), stop.Token);
                    if (route == "/slow") { Slow.TrySetResult(); await Task.Delay(TimeSpan.FromSeconds(5), stop.Token); }
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(bytes), stop.Token);
                }
                catch (Exception e) when (e is IOException or OperationCanceledException or AuthenticationException) { }
            }
        }
        public async ValueTask DisposeAsync()
        {
            stop.Cancel(); listener.Stop(); await serving; stop.Dispose(); Certificate.Dispose();
        }
    }
}
