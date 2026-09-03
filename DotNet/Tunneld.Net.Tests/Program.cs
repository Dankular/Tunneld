using Tunneld.Net.Config;
using Tunneld.Net.Ingress;
using Tunneld.Net.Userspace;
using Tunneld.Net.WireGuard;

var tests = new (string Name, Func<Task> Test)[]
{
    ("X25519 RFC vector", () => { TestX25519Vector(); return Task.CompletedTask; }),
    ("WireGuard key format", () => { TestWireGuardKeyFormat(); return Task.CompletedTask; }),
    ("Config load applies defaults", () => { TestConfigLoad(); return Task.CompletedTask; }),
    ("Ingress matching", () => { TestIngressMatching(); return Task.CompletedTask; }),
    ("IO.NET.TCPIP POC loopback", TestIoNetTcpipPoc),
};

foreach (var (name, test) in tests)
{
    await test();
    Console.WriteLine($"ok {name}");
}

return 0;

static void TestX25519Vector()
{
    var scalar = Convert.FromHexString("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    var u = Convert.FromHexString("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d1ab1c4c");
    var expected = "384b289c8a7748eea3b4a3e4d8c8733854403e3be7355c448c101136ead8fd58";
    var actual = Convert.ToHexString(WireGuardKey.X25519(scalar, u)).ToLowerInvariant();
    Assert(actual == expected, $"X25519 = {actual}, want {expected}");
}

static void TestWireGuardKeyFormat()
{
    var key = WireGuardKey.Generate();
    Assert(key.ToString().Length == 44, "private key should be base64 WireGuard length");
    Assert(key.PublicKey.Length == 44, "public key should be base64 WireGuard length");
    WireGuardKey.ParseBase64(key.ToString());
    WireGuardKey.ParseBase64(key.PublicKey);
}

static void TestConfigLoad()
{
    var dir = Directory.CreateTempSubdirectory();
    var path = Path.Combine(dir.FullName, "tunneld.yaml");
    var privateKey = WireGuardKey.Generate();
    var peerKey = WireGuardKey.Generate();
    File.WriteAllText(path, $"""
    wireguard:
      private_key: "{privateKey}"
      address: "10.100.0.5/32"
      dns: ["10.100.0.1"]
      peer:
        public_key: "{peerKey.PublicKey}"
        endpoint: "gateway.example.com:51820"
        allowed_ips: ["10.100.0.0/24"]
        persistent_keepalive: 25
    dns:
      enabled: true
      server: "10.100.0.1:53"
      zone: "example.internal."
      tsig:
        key_name: "abcd."
        secret: "c2VjcmV0"
      refresh_interval: 5m
    ingress:
      - hostname: "app.example.internal"
        path: "^/api"
        service: "http://127.0.0.1:8080"
      - service: "http_status:404"
    """);

    var config = ConfigLoader.Load(path);
    Assert(config.WireGuard.MTU == 1420, "MTU default");
    Assert(config.HTTP.ListenPort == 80, "HTTP listen port default");
    Assert(config.DNS.RefreshInterval == TimeSpan.FromMinutes(5), "duration parse");
}

static void TestIngressMatching()
{
    var rules = IngressRule.Compile([
        new IngressRuleConfig { Hostname = "app.example.internal", PathRegex = "^/api", Service = "http://127.0.0.1:8080" },
        new IngressRuleConfig { Service = "http_status:404" },
    ]);
    Assert(rules[0].Matches("app.example.internal", "/api/users"), "host/path match");
    Assert(!rules[0].Matches("app.example.internal", "/other"), "path mismatch");
    Assert(rules[1].Matches("anything", "/other"), "catch-all match");
}

static async Task TestIoNetTcpipPoc()
{
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    var result = await IoNetTcpipPoc.RunAsync(0, cts.Token);
    Assert(result.RequestText == "tunneld.net io.net.tcpip poc", "IO.NET.TCPIP request text");
    Assert(result.ResponseText == "echo:tunneld.net io.net.tcpip poc", "IO.NET.TCPIP response text");
}

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new Exception(message);
    }
}
