using Tunneld.Net.Config;
using Tunneld.Net.Runtime;
using Tunneld.Net.Userspace;
using Tunneld.Net.WireGuard;

namespace Tunneld.Net;

internal static class Program
{
    private const string DefaultConfigPath = "/etc/tunneld/tunneld.yaml";

    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 0)
        {
            Usage();
            return 2;
        }

        try
        {
            return args[0] switch
            {
                "run" => await Run(args[1..]),
                "validate" => Validate(args[1..]),
                "genkey" => GenKey(args[1..]),
                "poc-ionet-tcpip" => await PocIoNetTcpip(args[1..]),
                "version" => Version(),
                "-h" or "--help" or "help" => Help(),
                _ => Unknown(args[0]),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"tunneld.net: {args[0]}: {ex.Message}");
            return 1;
        }
    }

    private static async Task<int> Run(string[] args)
    {
        var configPath = Option(args, "--config", DefaultConfigPath);
        var config = ConfigLoader.Load(configPath);
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        var daemon = new HostNetworkDaemon(config, Console.Error);
        await daemon.RunAsync(cts.Token);
        return 0;
    }

    private static int Validate(string[] args)
    {
        var configPath = Option(args, "--config", DefaultConfigPath);
        var config = ConfigLoader.Load(configPath);
        Console.WriteLine($"tunneld.net: {configPath} is valid ({config.Ingress.Count} ingress rule(s))");
        return 0;
    }

    private static int GenKey(string[] args)
    {
        RequireNoArgs(args);
        var key = WireGuardKey.Generate();
        Console.WriteLine($"PrivateKey: {key}");
        Console.WriteLine($"PublicKey:  {key.PublicKey}");
        return 0;
    }

    private static async Task<int> PocIoNetTcpip(string[] args)
    {
        var portValue = Option(args, "--port", "0");
        if (!int.TryParse(portValue, out var port) || port < 0 || port > 65535)
        {
            throw new ArgumentException("--port must be 0..65535");
        }

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var result = await IoNetTcpipPoc.RunAsync(port, cts.Token);
        Console.WriteLine($"IO.NET.TCPIP POC OK on 127.0.0.1:{result.Port}");
        Console.WriteLine($"request:  {result.RequestText}");
        Console.WriteLine($"response: {result.ResponseText}");
        return 0;
    }

    private static int Version()
    {
        Console.WriteLine($"tunneld.net {VersionInfo.String()}");
        return 0;
    }

    private static int Help()
    {
        Usage();
        return 0;
    }

    private static int Unknown(string command)
    {
        Console.Error.WriteLine($"tunneld.net: unknown command \"{command}\"");
        Console.Error.WriteLine();
        Usage();
        return 2;
    }

    private static string Option(string[] args, string name, string defaultValue)
    {
        var value = defaultValue;
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == name)
            {
                if (i + 1 >= args.Length)
                {
                    throw new ArgumentException($"{name} requires a value");
                }
                value = args[++i];
                continue;
            }
            throw new ArgumentException($"unknown option {args[i]}");
        }
        return value;
    }

    private static void RequireNoArgs(string[] args)
    {
        if (args.Length != 0)
        {
            throw new ArgumentException($"unexpected argument {args[0]}");
        }
    }

    private static void Usage()
    {
        Console.Error.Write("""
        tunneld.net - C# Tunneld port

        Usage:
          tunneld.net run --config <path>       Run the host-network proxy runner
          tunneld.net validate --config <path>  Validate a tunneld.yaml file
          tunneld.net genkey                    Generate a WireGuard keypair
          tunneld.net poc-ionet-tcpip           Run an IO.NET.TCPIP loopback POC
          tunneld.net version                   Print the tunneld.net version

        """);
    }
}
