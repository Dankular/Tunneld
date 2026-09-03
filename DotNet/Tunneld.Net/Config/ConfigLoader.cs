using System.Net;
using System.Text.RegularExpressions;
using Tunneld.Net.WireGuard;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Tunneld.Net.Config;

public static class ConfigLoader
{
    public static TunneldConfig Load(string path)
    {
        var yaml = File.ReadAllText(path);
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .WithTypeConverter(new DurationYamlConverter())
            .Build();
        var config = deserializer.Deserialize<TunneldConfig>(yaml) ?? new TunneldConfig();
        ApplyDefaults(config);
        Validate(config);
        return config;
    }

    public static void ApplyDefaults(TunneldConfig config)
    {
        if (config.WireGuard.MTU == 0)
        {
            config.WireGuard.MTU = 1420;
        }
        if (config.DNS.TTL == 0)
        {
            config.DNS.TTL = 60;
        }
        if (config.HTTP.ListenPort == 0)
        {
            config.HTTP.ListenPort = 80;
        }
        if (config.HTTP.TLS.Enabled && config.HTTP.TLS.ListenPort == 0)
        {
            config.HTTP.TLS.ListenPort = 443;
        }
        if (string.IsNullOrWhiteSpace(config.Log.Level))
        {
            config.Log.Level = "info";
        }
    }

    public static void Validate(TunneldConfig config)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(config.WireGuard.PrivateKey))
        {
            errors.Add("wireguard.private_key is required");
        }
        else
        {
            Try(() => WireGuardKey.ParseBase64(config.WireGuard.PrivateKey), errors, "wireguard.private_key");
        }

        if (string.IsNullOrWhiteSpace(config.WireGuard.Address))
        {
            errors.Add("wireguard.address is required");
        }
        else
        {
            Try(() => Cidr.Parse(config.WireGuard.Address), errors, "wireguard.address");
        }

        if (string.IsNullOrWhiteSpace(config.WireGuard.Peer.PublicKey))
        {
            errors.Add("wireguard.peer.public_key is required");
        }
        else
        {
            Try(() => WireGuardKey.ParseBase64(config.WireGuard.Peer.PublicKey), errors, "wireguard.peer.public_key");
        }
        if (string.IsNullOrWhiteSpace(config.WireGuard.Peer.Endpoint))
        {
            errors.Add("wireguard.peer.endpoint is required");
        }
        if (config.WireGuard.Peer.AllowedIPs.Count == 0)
        {
            errors.Add("wireguard.peer.allowed_ips must have at least one entry");
        }
        foreach (var allowedIp in config.WireGuard.Peer.AllowedIPs)
        {
            Try(() => Cidr.Parse(allowedIp), errors, $"wireguard.peer.allowed_ips: {allowedIp}");
        }
        foreach (var dns in config.WireGuard.DNS)
        {
            if (!IPAddress.TryParse(dns, out _))
            {
                errors.Add($"wireguard.dns: {dns} is not an IP address");
            }
        }

        if (config.DNS.Enabled)
        {
            if (string.IsNullOrWhiteSpace(config.DNS.Server))
            {
                errors.Add("dns.server is required when dns.enabled is true");
            }
            if (string.IsNullOrWhiteSpace(config.DNS.Zone))
            {
                errors.Add("dns.zone is required when dns.enabled is true");
            }
            if (string.IsNullOrWhiteSpace(config.DNS.TSIG.KeyName) || string.IsNullOrWhiteSpace(config.DNS.TSIG.Secret))
            {
                errors.Add("dns.tsig.key_name and dns.tsig.secret are required when dns.enabled is true");
            }
            if (config.DNS.RecordType is { Length: > 0 } && config.DNS.RecordType != "A" && config.DNS.RecordType != "AAAA")
            {
                errors.Add($"dns.record_type: must be A or AAAA, got {config.DNS.RecordType}");
            }
        }

        if (config.Ingress.Count == 0)
        {
            errors.Add("ingress must have at least one rule");
        }
        for (var i = 0; i < config.Ingress.Count; i++)
        {
            var rule = config.Ingress[i];
            var last = i == config.Ingress.Count - 1;
            if (string.IsNullOrWhiteSpace(rule.Hostname) && !last)
            {
                errors.Add($"ingress[{i}]: only the last rule may omit hostname (catch-all)");
            }
            if (string.IsNullOrWhiteSpace(rule.Service))
            {
                errors.Add($"ingress[{i}]: service is required");
                continue;
            }
            if (rule.PathRegex.Length > 0)
            {
                Try(() => Regex.Match("", rule.PathRegex), errors, $"ingress[{i}].path");
            }
            if (rule.Service.StartsWith("tcp://", StringComparison.OrdinalIgnoreCase) && rule.ListenPort == 0)
            {
                errors.Add($"ingress[{i}]: listen_port is required for tcp:// services");
            }
            else if (!rule.Service.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                     && !rule.Service.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                     && !rule.Service.StartsWith("tcp://", StringComparison.OrdinalIgnoreCase)
                     && !rule.Service.StartsWith("http_status:", StringComparison.OrdinalIgnoreCase))
            {
                errors.Add($"ingress[{i}]: service must start with http://, https://, tcp://, or http_status:");
            }
        }

        if (config.Log.Level is { Length: > 0 } && config.Log.Level is not ("debug" or "info" or "warn" or "error"))
        {
            errors.Add("log.level must be debug, info, warn, or error");
        }

        if (errors.Count > 0)
        {
            throw new InvalidOperationException(string.Join("; ", errors));
        }
    }

    private static void Try(Action action, List<string> errors, string label)
    {
        try
        {
            action();
        }
        catch (Exception ex)
        {
            errors.Add($"{label}: {ex.Message}");
        }
    }
}
