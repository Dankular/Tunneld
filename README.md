# Tunneld

An outbound-only reverse proxy daemon, playing the same role cloudflared
plays for Cloudflare Tunnel - except it dials out over **your own
WireGuard network** and publishes hostnames into **your own DNS server**,
instead of Cloudflare's edge.

Run it on a machine behind NAT/a firewall, with local services you want to
expose (an internal web app, Grafana, SSH, ...). It:

1. Brings up a WireGuard tunnel to a gateway you run, entirely in
   userspace (no root, no OS TUN device - see [How it works](#how-it-works)).
2. Publishes each configured hostname into your DNS server via an
   RFC 2136 dynamic update (TSIG-signed), pointed at this node's address
   inside the tunnel.
3. Reverse-proxies inbound requests arriving over the tunnel to local
   services, matched by hostname (and optionally path), the way
   cloudflared's `ingress` rule list works.

This project is the client-side connector only. It expects a WireGuard
gateway and an RFC 2136-capable DNS server to already exist on your
network; it doesn't stand those up for you.

> The ingress-rule-list shape and the "dial out, no inbound ports needed"
> model are this project's own design, deliberately similar to
> cloudflared's for a familiar workflow - not verified against
> cloudflared's source, since the whole point here is to plug in different
> transport (WireGuard) and DNS (RFC 2136) backends.

## Quick start

```sh
go build -o tunneld ./cmd/tunneld
./tunneld genkey            # generate this node's WireGuard keypair
cp configs/tunneld.example.yaml tunneld.yaml
$EDITOR tunneld.yaml        # fill in your keys, gateway endpoint, ingress rules
./tunneld validate --config tunneld.yaml
./tunneld run --config tunneld.yaml
```

See [`configs/tunneld.example.yaml`](configs/tunneld.example.yaml) for the
full, commented config schema, and [`systemd/tunneld.service`](systemd/tunneld.service)
for running it as a system service.

## Ingress rules

```yaml
ingress:
  - hostname: "app.example.internal"
    service: "http://127.0.0.1:8080"

  - hostname: "grafana.example.internal"
    path: "^/api/.*"          # optional regex, matched against the request path
    service: "http://127.0.0.1:9090"

  - hostname: "ssh.example.internal"
    service: "tcp://127.0.0.1:22"
    listen_port: 2222          # tcp:// services need their own listener port

  - service: "http_status:404" # catch-all: only the last rule may omit hostname
```

Rules are matched top to bottom by hostname (Host header / TLS SNI), then
by path regex if given. `http://`/`https://` services share one reverse
proxy listener (`http.listen_port`, default 80, and `http.tls.listen_port`
if TLS termination is enabled); each `tcp://` service gets its own
listener on `listen_port`.

## How it works

The WireGuard tunnel runs entirely in userspace via
[`golang.zx2c4.com/wireguard`](https://pkg.go.dev/golang.zx2c4.com/wireguard)'s
`tun/netstack` package: a real WireGuard handshake and encrypted UDP
transport, but the "TUN device" on this end is a gVisor-backed virtual
network stack living inside the process, not an OS network interface. That
means:

- No root and no `CAP_NET_ADMIN` - the daemon can run as an unprivileged
  system user (see the systemd unit).
- Listening on port 80/443 "inside the tunnel" doesn't need
  `CAP_NET_BIND_SERVICE` either, since it's gVisor's own userspace
  TCP/IP stack, not a real `bind()` on those ports.
- Local services this node proxies *to* are dialed over the ordinary OS
  network (`127.0.0.1:8080`, etc.) - only the *inbound* side, where your
  gateway forwards traffic to this node, goes through the virtual
  WireGuard network.

DNS publication uses [`github.com/miekg/dns`](https://pkg.go.dev/github.com/miekg/dns)
to send RFC 2136 dynamic updates (TSIG-signed with RFC 2845), replacing
whatever A/AAAA records exist at each ingress hostname with this node's
WireGuard address. It re-sends on `dns.refresh_interval` so the record
self-heals if it's ever lost.

## Repository layout

```
cmd/tunneld/            CLI entrypoint (run / validate / genkey / version)
internal/config/        tunneld.yaml schema, parsing, validation
internal/wgkey/         WireGuard keypair generation (RFC 7748 X25519 clamping)
internal/wgtun/         userspace WireGuard device + netstack, status/handshake reporting
internal/dnsupdate/     RFC 2136 dynamic DNS client
internal/ingress/       ingress rule compilation and matching
internal/proxy/         HTTP reverse proxy + raw TCP passthrough
internal/daemon/        wires the above together; run loop, graceful shutdown
configs/                example tunneld.yaml
systemd/                systemd unit
```

## Development

```sh
make build   # bin/tunneld
make test    # go test -race ./...
make lint    # gofmt check + go vet + tests
```

The test suite includes an end-to-end test
(`internal/daemon/daemon_test.go`) that stands up a second, independent
WireGuard device as a fake gateway, performs a real handshake with the
daemon under test over loopback UDP, and dials the daemon's internal
address the way a real gateway would - proving the tunnel, HTTP proxying,
and DNS publication actually work together, not just their units in
isolation.

## License

MIT, see [LICENSE](LICENSE).
