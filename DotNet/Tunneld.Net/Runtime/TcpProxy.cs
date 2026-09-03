using System.Net.Sockets;

namespace Tunneld.Net.Runtime;

public static class TcpProxy
{
    public static async Task ForwardAsync(TcpClient inbound, string targetHost, int targetPort, CancellationToken cancellationToken)
    {
        using (inbound)
        using (var outbound = new TcpClient())
        {
            await outbound.ConnectAsync(targetHost, targetPort, cancellationToken);
            await using var inboundStream = inbound.GetStream();
            await using var outboundStream = outbound.GetStream();
            var a = inboundStream.CopyToAsync(outboundStream, cancellationToken);
            var b = outboundStream.CopyToAsync(inboundStream, cancellationToken);
            await Task.WhenAny(a, b);
        }
    }
}
