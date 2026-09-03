using System.Security.Cryptography.X509Certificates;
using Tunneld.Net.Config;

namespace Tunneld.Net.Runtime;

public sealed class TlsCertificateStore
{
    private readonly Dictionary<string, X509Certificate2> _certificates;

    public TlsCertificateStore(IEnumerable<CertPairConfig> certs)
    {
        _certificates = certs.ToDictionary(
            c => c.Hostname.TrimEnd('.').ToLowerInvariant(),
            c => X509Certificate2.CreateFromPemFile(c.CertFile, c.KeyFile));
    }

    public X509Certificate2 DefaultCertificate =>
        _certificates.Count == 0
            ? throw new InvalidOperationException("http.tls.certs must contain at least one certificate when TLS is enabled")
            : _certificates.Values.First();

    public X509Certificate2 Select(string? serverName)
    {
        if (!string.IsNullOrWhiteSpace(serverName) &&
            _certificates.TryGetValue(serverName.TrimEnd('.').ToLowerInvariant(), out var cert))
        {
            return cert;
        }
        return DefaultCertificate;
    }
}
