using System.Net;
using System.Net.Sockets;
using Tunneld.Net.Config;
using Tunneld.Net.DnsUpdate;
using Tunneld.Net.Ingress;

namespace Tunneld.Net.Runtime;

public sealed class HostNetworkDaemon
{
    private readonly TunneldConfig _config;
    private readonly TextWriter _log;
    private readonly IReadOnlyList<IngressRule> _rules;

    public HostNetworkDaemon(TunneldConfig config, TextWriter log)
    {
        _config = config;
        _log = log;
        _rules = IngressRule.Compile(config.Ingress);
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var tasks = new List<Task>();
        if (_config.DNS.Enabled)
        {
            tasks.Add(RunDnsAsync(cancellationToken));
        }
        tasks.Add(RunHttpAsync(cancellationToken));
        if (_config.HTTP.TLS.Enabled)
        {
            tasks.Add(RunHttpsAsync(cancellationToken));
        }
        foreach (var tcpRule in _rules.Where(r => r.Kind == ServiceKind.Tcp))
        {
            tasks.Add(RunTcpAsync(tcpRule, cancellationToken));
        }
        await Task.WhenAll(tasks);
    }

    private async Task RunDnsAsync(CancellationToken cancellationToken)
    {
        var client = new DnsUpdateClient(_config.DNS);
        var address = Cidr.Parse(_config.WireGuard.Address).Address;
        await PublishDnsAsync(client, address, cancellationToken);
        if (_config.DNS.RefreshInterval <= TimeSpan.Zero)
        {
            return;
        }
        using var timer = new PeriodicTimer(_config.DNS.RefreshInterval);
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            await PublishDnsAsync(client, address, cancellationToken);
        }
    }

    private async Task PublishDnsAsync(DnsUpdateClient client, IPAddress address, CancellationToken cancellationToken)
    {
        foreach (var hostname in _rules.Select(r => r.Hostname).Where(h => !string.IsNullOrWhiteSpace(h)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            await client.UpsertAsync(hostname, address, cancellationToken);
            _log.WriteLine($"info: DNS record published {hostname} -> {address}");
        }
    }

    private async Task RunHttpAsync(CancellationToken cancellationToken)
    {
        var address = string.IsNullOrWhiteSpace(_config.HTTP.ListenAddr) ? "127.0.0.1" : _config.HTTP.ListenAddr;
        var prefix = $"http://{address}:{_config.HTTP.ListenPort}/";
        using var listener = new HttpListener();
        listener.Prefixes.Add(prefix);
        listener.Start();
        _log.WriteLine($"info: HTTP ingress listening on {prefix}");

        using var registration = cancellationToken.Register(() =>
        {
            try { listener.Stop(); } catch (ObjectDisposedException) { }
        });

        while (!cancellationToken.IsCancellationRequested)
        {
            HttpListenerContext context;
            try
            {
                context = await listener.GetContextAsync();
            }
            catch (HttpListenerException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            _ = Task.Run(() => HandleHttpAsync(context, cancellationToken), cancellationToken);
        }
    }

    private Task RunHttpsAsync(CancellationToken cancellationToken)
    {
        var ip = string.IsNullOrWhiteSpace(_config.HTTP.ListenAddr)
            ? IPAddress.Loopback
            : IPAddress.Parse(_config.HTTP.ListenAddr);
        var certs = new TlsCertificateStore(_config.HTTP.TLS.Certs);
        var server = new TlsHttpServer(ip, _config.HTTP.TLS.ListenPort, _rules, certs, _log);
        return server.RunAsync(cancellationToken);
    }

    private async Task HandleHttpAsync(HttpListenerContext context, CancellationToken cancellationToken)
    {
        var host = context.Request.Headers["Host"] ?? "";
        var path = context.Request.Url?.AbsolutePath ?? "/";
        var rule = _rules.FirstOrDefault(r => (r.Kind == ServiceKind.Http || r.Kind == ServiceKind.FixedStatus) && r.Matches(host, path))
                   ?? _rules.FirstOrDefault(r => r.Matches(host, path));

        if (rule is null)
        {
            context.Response.StatusCode = 404;
            context.Response.Close();
            return;
        }
        if (rule.Kind == ServiceKind.FixedStatus)
        {
            context.Response.StatusCode = rule.FixedStatus ?? 500;
            context.Response.Close();
            return;
        }
        await ReverseProxy.ForwardAsync(context, rule.Service, cancellationToken);
    }

    private async Task RunTcpAsync(IngressRule rule, CancellationToken cancellationToken)
    {
        var target = new Uri(rule.Service);
        var listener = new TcpListener(IPAddress.Loopback, rule.ListenPort);
        listener.Start();
        _log.WriteLine($"info: TCP ingress listening on 127.0.0.1:{rule.ListenPort} -> {target.Host}:{target.Port}");

        using var registration = cancellationToken.Register(() => listener.Stop());
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient inbound;
            try
            {
                inbound = await listener.AcceptTcpClientAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            _ = Task.Run(() => TcpProxy.ForwardAsync(inbound, target.Host, target.Port, cancellationToken), cancellationToken);
        }
    }
}
