using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using Tunneld.Net.Ingress;

namespace Tunneld.Net.Runtime;

public sealed class TlsHttpServer
{
    private readonly IPAddress _address;
    private readonly int _port;
    private readonly IReadOnlyList<IngressRule> _rules;
    private readonly TlsCertificateStore _certificates;
    private readonly TextWriter _log;

    public TlsHttpServer(IPAddress address, int port, IReadOnlyList<IngressRule> rules, TlsCertificateStore certificates, TextWriter log)
    {
        _address = address;
        _port = port;
        _rules = rules;
        _certificates = certificates;
        _log = log;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var listener = new TcpListener(_address, _port);
        listener.Start();
        _log.WriteLine($"info: HTTPS ingress listening on {_address}:{_port}");
        using var registration = cancellationToken.Register(() => listener.Stop());
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            _ = Task.Run(() => HandleAsync(client, cancellationToken), cancellationToken);
        }
    }

    private async Task HandleAsync(TcpClient client, CancellationToken cancellationToken)
    {
        using (client)
        await using (var stream = client.GetStream())
        await using (var ssl = new SslStream(stream, false))
        {
            var options = new SslServerAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ServerCertificateSelectionCallback = (_, name) => _certificates.Select(name),
            };
            await ssl.AuthenticateAsServerAsync(options, cancellationToken);
            var request = await ReadRequestAsync(ssl, cancellationToken);
            if (request is null)
            {
                return;
            }
            var rule = _rules.FirstOrDefault(r => (r.Kind == ServiceKind.Http || r.Kind == ServiceKind.FixedStatus) && r.Matches(request.Host, request.Path));
            if (rule is null)
            {
                await WriteFixedAsync(ssl, 404, cancellationToken);
                return;
            }
            if (rule.Kind == ServiceKind.FixedStatus)
            {
                await WriteFixedAsync(ssl, rule.FixedStatus ?? 500, cancellationToken);
                return;
            }
            await TlsReverseProxy.ForwardAsync(ssl, request, rule.Service, cancellationToken);
        }
    }

    private static async Task<HttpRequest?> ReadRequestAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var tmp = new byte[1024];
        while (buffer.Length < 64 * 1024)
        {
            var read = await stream.ReadAsync(tmp, cancellationToken);
            if (read == 0)
            {
                return null;
            }
            buffer.Write(tmp, 0, read);
            var text = Encoding.ASCII.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
            var marker = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (marker >= 0)
            {
                var head = text[..marker];
                var lines = head.Split("\r\n");
                var first = lines[0].Split(' ');
                if (first.Length < 2)
                {
                    return null;
                }
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var line in lines.Skip(1))
                {
                    var idx = line.IndexOf(':');
                    if (idx > 0)
                    {
                        headers[line[..idx]] = line[(idx + 1)..].Trim();
                    }
                }
                headers.TryGetValue("Host", out var host);
                return new HttpRequest(first[0], first[1], host ?? "", headers, buffer.ToArray()[(marker + 4)..]);
            }
        }
        return null;
    }

    private static async Task WriteFixedAsync(Stream stream, int status, CancellationToken cancellationToken)
    {
        var reason = ReasonPhrases.Get(status);
        var payload = Encoding.UTF8.GetBytes($"{status} {reason}\n");
        var head = Encoding.ASCII.GetBytes($"HTTP/1.1 {status} {reason}\r\nContent-Length: {payload.Length}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(head, cancellationToken);
        await stream.WriteAsync(payload, cancellationToken);
    }
}

public sealed record HttpRequest(string Method, string RawTarget, string Host, IReadOnlyDictionary<string, string> Headers, byte[] Body)
{
    public string Path => RawTarget.Split('?', 2)[0];
}

public static class ReasonPhrases
{
    public static string Get(int status) => status switch
    {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        502 => "Bad Gateway",
        _ => "Status",
    };
}
