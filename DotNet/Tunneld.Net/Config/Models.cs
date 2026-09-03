using YamlDotNet.Serialization;

namespace Tunneld.Net.Config;

public sealed class TunneldConfig
{
    [YamlMember(Alias = "wireguard")]
    public WireGuardConfig WireGuard { get; set; } = new();
    [YamlMember(Alias = "dns")]
    public DnsConfig DNS { get; set; } = new();
    [YamlMember(Alias = "ingress")]
    public List<IngressRuleConfig> Ingress { get; set; } = [];
    [YamlMember(Alias = "http")]
    public HttpConfig HTTP { get; set; } = new();
    [YamlMember(Alias = "log")]
    public LogConfig Log { get; set; } = new();
}

public sealed class WireGuardConfig
{
    [YamlMember(Alias = "private_key")]
    public string PrivateKey { get; set; } = "";
    [YamlMember(Alias = "address")]
    public string Address { get; set; } = "";
    [YamlMember(Alias = "dns")]
    public List<string> DNS { get; set; } = [];
    [YamlMember(Alias = "mtu")]
    public int MTU { get; set; }
    [YamlMember(Alias = "listen_port")]
    public int ListenPort { get; set; }
    [YamlMember(Alias = "peer")]
    public PeerConfig Peer { get; set; } = new();
}

public sealed class PeerConfig
{
    [YamlMember(Alias = "public_key")]
    public string PublicKey { get; set; } = "";
    [YamlMember(Alias = "endpoint")]
    public string Endpoint { get; set; } = "";
    [YamlMember(Alias = "allowed_ips")]
    public List<string> AllowedIPs { get; set; } = [];
    [YamlMember(Alias = "persistent_keepalive")]
    public int PersistentKeepalive { get; set; }
}

public sealed class DnsConfig
{
    [YamlMember(Alias = "enabled")]
    public bool Enabled { get; set; }
    [YamlMember(Alias = "server")]
    public string Server { get; set; } = "";
    [YamlMember(Alias = "zone")]
    public string Zone { get; set; } = "";
    [YamlMember(Alias = "tsig")]
    public TsigConfig TSIG { get; set; } = new();
    [YamlMember(Alias = "ttl")]
    public int TTL { get; set; }
    [YamlMember(Alias = "refresh_interval")]
    public TimeSpan RefreshInterval { get; set; }
    [YamlMember(Alias = "record_type")]
    public string RecordType { get; set; } = "";
    [YamlMember(Alias = "deregister_on_exit")]
    public bool DeregisterOnExit { get; set; }
}

public sealed class TsigConfig
{
    [YamlMember(Alias = "key_name")]
    public string KeyName { get; set; } = "";
    [YamlMember(Alias = "algorithm")]
    public string Algorithm { get; set; } = "";
    [YamlMember(Alias = "secret")]
    public string Secret { get; set; } = "";
}

public sealed class IngressRuleConfig
{
    [YamlMember(Alias = "hostname")]
    public string Hostname { get; set; } = "";
    [YamlMember(Alias = "path")]
    public string PathRegex { get; set; } = "";
    [YamlMember(Alias = "service")]
    public string Service { get; set; } = "";
    [YamlMember(Alias = "listen_port")]
    public int ListenPort { get; set; }
}

public sealed class HttpConfig
{
    [YamlMember(Alias = "listen_addr")]
    public string ListenAddr { get; set; } = "";
    [YamlMember(Alias = "listen_port")]
    public int ListenPort { get; set; }
    [YamlMember(Alias = "tls")]
    public HttpTlsConfig TLS { get; set; } = new();
}

public sealed class HttpTlsConfig
{
    [YamlMember(Alias = "enabled")]
    public bool Enabled { get; set; }
    [YamlMember(Alias = "listen_port")]
    public int ListenPort { get; set; }
    [YamlMember(Alias = "certs")]
    public List<CertPairConfig> Certs { get; set; } = [];
}

public sealed class CertPairConfig
{
    [YamlMember(Alias = "hostname")]
    public string Hostname { get; set; } = "";
    [YamlMember(Alias = "cert_file")]
    public string CertFile { get; set; } = "";
    [YamlMember(Alias = "key_file")]
    public string KeyFile { get; set; } = "";
}

public sealed class LogConfig
{
    [YamlMember(Alias = "level")]
    public string Level { get; set; } = "";
}
