using System.Net;
using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
using ARSoft.Tools.Net.Dns.DynamicUpdate;
using Tunneld.Net.Config;

namespace Tunneld.Net.DnsUpdate;

public sealed class DnsUpdateClient
{
    private readonly DnsConfig _config;
    private readonly DnsClient _client;
    private readonly TSigAlgorithm _algorithm;
    private readonly byte[] _secret;

    public DnsUpdateClient(DnsConfig config)
    {
        _config = config;
        var server = ParseServer(config.Server);
        _client = new DnsClient(server.Address, 5000);
        _algorithm = ParseAlgorithm(config.TSIG.Algorithm);
        _secret = Convert.FromBase64String(config.TSIG.Secret);
    }

    public async Task UpsertAsync(string hostname, IPAddress address, CancellationToken cancellationToken)
    {
        var msg = BaseMessage();
        var name = DomainName.Parse(Fqdn(hostname));
        var recordType = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? RecordType.A
            : RecordType.Aaaa;
        msg.Updates.Add(new DeleteAllRecordsUpdate(name, recordType));
        msg.Updates.Add(new AddRecordUpdate(recordType == RecordType.A
            ? new ARecord(name, _config.TTL, address)
            : new AaaaRecord(name, _config.TTL, address)));
        await SendAsync(msg, cancellationToken);
    }

    public async Task DeleteAsync(string hostname, CancellationToken cancellationToken)
    {
        var msg = BaseMessage();
        var name = DomainName.Parse(Fqdn(hostname));
        msg.Updates.Add(new DeleteAllRecordsUpdate(name, RecordType.A));
        msg.Updates.Add(new DeleteAllRecordsUpdate(name, RecordType.Aaaa));
        await SendAsync(msg, cancellationToken);
    }

    private DnsUpdateMessage BaseMessage()
    {
        var msg = new DnsUpdateMessage
        {
            ZoneName = DomainName.Parse(Fqdn(_config.Zone)),
        };
        msg.TSigOptions = new TSigRecord(
            DomainName.Parse(Fqdn(_config.TSIG.KeyName)),
            _algorithm,
            DateTime.UtcNow,
            TimeSpan.FromMinutes(5),
            msg.TransactionID,
            ReturnCode.NoError,
            [],
            _secret);
        return msg;
    }

    private async Task SendAsync(DnsUpdateMessage msg, CancellationToken cancellationToken)
    {
        var response = await _client.SendUpdateAsync(msg, cancellationToken);
        if (response is null)
        {
            throw new InvalidOperationException($"DNS update to {_config.Server} timed out");
        }
        if (response.ReturnCode != ReturnCode.NoError)
        {
            throw new InvalidOperationException($"DNS update to {_config.Server} failed: {response.ReturnCode}");
        }
    }

    private static IPEndPoint ParseServer(string server)
    {
        var defaultPort = 53;
        if (IPEndPoint.TryParse(server, out var endpoint))
        {
            return endpoint.Port == 0 ? new IPEndPoint(endpoint.Address, defaultPort) : endpoint;
        }
        var parts = server.Split(':', 2);
        var host = parts[0];
        var port = parts.Length == 2 && int.TryParse(parts[1], out var parsedPort) ? parsedPort : defaultPort;
        var addresses = Dns.GetHostAddresses(host);
        if (addresses.Length == 0)
        {
            throw new InvalidOperationException($"DNS server {server} did not resolve");
        }
        return new IPEndPoint(addresses[0], port);
    }

    private static TSigAlgorithm ParseAlgorithm(string algorithm)
    {
        return algorithm.TrimEnd('.').ToLowerInvariant() switch
        {
            "" or "hmac-sha256" => TSigAlgorithm.Sha256,
            "hmac-sha1" => TSigAlgorithm.Sha1,
            "hmac-sha224" => TSigAlgorithm.Sha224,
            "hmac-sha384" => TSigAlgorithm.Sha384,
            "hmac-sha512" => TSigAlgorithm.Sha512,
            _ => throw new InvalidOperationException($"unsupported TSIG algorithm {algorithm}"),
        };
    }

    private static string Fqdn(string value) => value.EndsWith('.') ? value : value + ".";
}
