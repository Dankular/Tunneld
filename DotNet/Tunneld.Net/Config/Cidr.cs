using System.Net;

namespace Tunneld.Net.Config;

public sealed record Cidr(IPAddress Address, int PrefixLength)
{
    public static Cidr Parse(string value)
    {
        var parts = value.Split('/', 2);
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var address))
        {
            throw new FormatException($"invalid CIDR {value}");
        }
        if (!int.TryParse(parts[1], out var prefixLength))
        {
            throw new FormatException($"invalid CIDR prefix {value}");
        }
        var max = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        if (prefixLength < 0 || prefixLength > max)
        {
            throw new FormatException($"CIDR prefix must be between 0 and {max}");
        }
        return new Cidr(address, prefixLength);
    }
}
