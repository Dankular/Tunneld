# Tunneld.Net

A C# port of the `tunneld` daemon surface.

Implemented:

- `run`, `validate`, `genkey`, and `version` CLI commands
- `tunneld.yaml` compatible schema parsing and validation
- WireGuard-compatible X25519 key generation and public key derivation
- ingress rule compilation and hostname/path matching
- HTTP reverse proxying for `http://` and `https://` local services
- raw TCP passthrough for `tcp://` services
- fixed `http_status:NNN` ingress responses
- RFC 2136 dynamic DNS publication via a managed DNS client
- TLS listener/SNI certificate loading
- `IO.NET.TCPIP` loopback POC command

Not yet implemented:

- the Go daemon's pure userspace WireGuard `tun/netstack` transport

The current `run` command is a host-network runner: it binds OS sockets on
`http.listen_addr` if set, otherwise `127.0.0.1`. It is useful for porting and
proxy validation, but it is not yet a full replacement for the Go daemon's
userspace WireGuard runtime.

`IO.NET.TCPIP` is included for a requested POC only. Its public API exposes
TCP client/server helpers over normal host TCP sockets, not a gVisor-style
packet-in/packet-out userspace TCP/IP stack. Keep it behind the POC boundary
until the managed WireGuard/netstack replacement is implemented.

## Userspace References

The managed userspace runtime should reference the Go daemon's gVisor netstack
behavior and QEMU/libslirp's packet-in, callback-out architecture, without
binding to either implementation. See `docs/userspace-netstack-references.md`
for the reference list and implementation milestones.

## Build

```powershell
dotnet build .\DotNet\Tunneld.Net\Tunneld.Net.csproj
```

## Test

```powershell
dotnet run --project .\DotNet\Tunneld.Net.Tests\Tunneld.Net.Tests.csproj
```

## Use

```powershell
dotnet run --project .\DotNet\Tunneld.Net -- genkey
dotnet run --project .\DotNet\Tunneld.Net -- validate --config tunneld.yaml
dotnet run --project .\DotNet\Tunneld.Net -- run --config tunneld.yaml
dotnet run --project .\DotNet\Tunneld.Net -- poc-ionet-tcpip
```
