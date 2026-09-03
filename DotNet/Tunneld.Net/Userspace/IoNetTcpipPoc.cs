using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Tunneld.Net.Userspace;

public sealed record IoNetTcpipPocResult(int Port, byte[] Request, byte[] Response)
{
    public string RequestText => Encoding.UTF8.GetString(Request);
    public string ResponseText => Encoding.UTF8.GetString(Response);
}

public static class IoNetTcpipPoc
{
    public static async Task<IoNetTcpipPocResult> RunAsync(int port, CancellationToken cancellationToken)
    {
        if (port == 0)
        {
            port = ReserveLoopbackPort();
        }

        var request = Encoding.UTF8.GetBytes("tunneld.net io.net.tcpip poc");
        var responsePrefix = Encoding.UTF8.GetBytes("echo:");
        var expected = responsePrefix.Concat(request).ToArray();
        var server = new IO.NET.TCPIPServer.TCPIPServer
        {
            ReadTimeout = 5000,
            WriteTimeout = 5000,
        };

        server.ClientRequestEvent += (_, e) =>
        {
            if (!e.Success)
            {
                return;
            }

            var response = responsePrefix.Concat(e.ReadBytes ?? []).ToArray();
            _ = Task.Run(async () => await server.ServerResponse(response, e.SocketArgs));
        };

        var start = await server.StartServer(port.ToString());
        if (!start.Success)
        {
            throw new InvalidOperationException($"IO.NET.TCPIP server failed to start: {start.ErrorMessage}");
        }

        try
        {
            var client = new IO.NET.TCPIPClient.TCPIPClient
            {
                ReadTimeout = 5000,
                WriteTimeout = 5000,
            };

            var result = await client.SendClientRequest(IPAddress.Loopback.ToString(), port.ToString(), request);
            if (!result.SuccessSend || !result.SuccessRead)
            {
                throw new InvalidOperationException($"IO.NET.TCPIP client failed: {result.ErrorMessage}");
            }
            if (!result.ReadBytes.AsSpan().SequenceEqual(expected))
            {
                throw new InvalidOperationException($"IO.NET.TCPIP response mismatch: {Encoding.UTF8.GetString(result.ReadBytes)}");
            }

            return new IoNetTcpipPocResult(port, request, result.ReadBytes);
        }
        finally
        {
            server.StopServer();
        }
    }

    private static int ReserveLoopbackPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
