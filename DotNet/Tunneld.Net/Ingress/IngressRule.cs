using System.Net;
using System.Text.RegularExpressions;
using Tunneld.Net.Config;

namespace Tunneld.Net.Ingress;

public enum ServiceKind
{
    Http,
    Tcp,
    FixedStatus,
}

public sealed class IngressRule
{
    private readonly Regex? _pathRegex;

    public IngressRule(string hostname, string service, int listenPort, string pathRegex)
    {
        Hostname = hostname;
        Service = service;
        ListenPort = listenPort;
        Kind = ParseKind(service);
        FixedStatus = Kind == ServiceKind.FixedStatus ? ParseStatus(service) : null;
        _pathRegex = string.IsNullOrWhiteSpace(pathRegex) ? null : new Regex(pathRegex, RegexOptions.Compiled);
    }

    public string Hostname { get; }
    public string Service { get; }
    public int ListenPort { get; }
    public ServiceKind Kind { get; }
    public int? FixedStatus { get; }

    public bool Matches(string host, string path)
    {
        if (!string.IsNullOrWhiteSpace(Hostname) && !SameHost(Hostname, host))
        {
            return false;
        }
        return _pathRegex is null || _pathRegex.IsMatch(path);
    }

    public static IReadOnlyList<IngressRule> Compile(IEnumerable<IngressRuleConfig> rules) =>
        rules.Select(r => new IngressRule(r.Hostname, r.Service, r.ListenPort, r.PathRegex)).ToList();

    private static bool SameHost(string expected, string actual)
    {
        actual = actual.Split(':', 2)[0];
        return string.Equals(expected.TrimEnd('.'), actual.TrimEnd('.'), StringComparison.OrdinalIgnoreCase);
    }

    private static ServiceKind ParseKind(string service)
    {
        if (service.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || service.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return ServiceKind.Http;
        }
        if (service.StartsWith("tcp://", StringComparison.OrdinalIgnoreCase))
        {
            return ServiceKind.Tcp;
        }
        return ServiceKind.FixedStatus;
    }

    private static int ParseStatus(string service)
    {
        var raw = service["http_status:".Length..];
        return int.TryParse(raw, out var status) ? status : (int)HttpStatusCode.InternalServerError;
    }
}
