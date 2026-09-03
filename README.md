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

This project is the client-side connector. For a repeatable gateway/client
setup flow, use
[`Tunneld-Provisioner`](https://github.com/Dankular/Tunneld-Provisioner) to
generate the gateway WireGuard/BIND artifacts and the per-client
`tunneld.yaml` files consumed by this daemon.

> The ingress-rule-list shape and the "dial out, no inbound ports needed"
> model are this project's own design, deliberately similar to
> cloudflared's for a familiar workflow - not verified against
> cloudflared's source, since the whole point here is to plug in different
> transport (WireGuard) and DNS (RFC 2136) backends.

## Quick start

### Provisioner-assisted

Use the provisioner when you want one topology file to produce both gateway
artifacts and daemon configs:

```sh
git clone https://github.com/Dankular/Tunneld-Provisioner.git
cd Tunneld-Provisioner
go build -o tunneld-provisioner ./cmd/tunneld-provisioner

./tunneld-provisioner genkey    # gateway keypair
./tunneld-provisioner genkey    # client keypair
./tunneld-provisioner gentsig   # UUID TSIG key name + base64 secret

cp configs/provisioner.example.yaml provisioner.yaml
$EDITOR provisioner.yaml

./tunneld-provisioner validate --config provisioner.yaml
./tunneld-provisioner render --config provisioner.yaml --out dist
```

The rendered tree contains gateway-side files and daemon-side config:

```text
dist/
  gateway/
    wireguard/wg0.conf
    bind/tunneld.keys
    bind/tunneld-zone.conf
  clients/
    apphost/tunneld.yaml
```

Install `dist/gateway/wireguard/wg0.conf` on your public gateway, merge the
BIND snippets into your authoritative DNS configuration, then copy the relevant
`dist/clients/<name>/tunneld.yaml` onto each machine running `tunneld`.

On the Windows deployment workstation used by this project, the provisioner can
deploy itself to the gateway with:

```powershell
.\scripts\deploy.ps1
```

That wrapper validates, pushes, cross-builds, uploads, uninstalls the active
remote provisioner install, reinstalls it, updates
`/opt/tunneld-provisioner/current`, and runs a smoke validation. To remove the
active provisioner install without replacing it:

```powershell
.\scripts\deploy.ps1 -UninstallOnly
```

### Manual daemon config

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

If you used the provisioner, validate and run the generated client config with
the daemon:

```sh
tunneld validate --config dist/clients/apphost/tunneld.yaml
tunneld run --config dist/clients/apphost/tunneld.yaml
```

## Deployment outline

On the gateway, install the rendered WireGuard config and bring the interface
up:

```sh
sudo install -m 0600 dist/gateway/wireguard/wg0.conf /etc/wireguard/wg0.conf
sudo systemctl enable --now wg-quick@wg0
sudo wg show wg0
```

If you use BIND for RFC 2136 updates, install the rendered TSIG key and include
the rendered zone policy from your named configuration:

```sh
sudo install -m 0600 dist/gateway/bind/tunneld.keys /etc/bind/tunneld.keys
sudo install -m 0644 dist/gateway/bind/tunneld-zone.conf /etc/bind/named.conf.tunneld-zone
sudo named-checkconf
sudo systemctl reload bind9
```

On each client host, install the daemon and the provisioner-rendered config:

```sh
sudo install -m 0755 tunneld /usr/local/bin/tunneld
sudo install -d -m 0750 /etc/tunneld
sudo install -m 0600 dist/clients/apphost/tunneld.yaml /etc/tunneld/tunneld.yaml
sudo install -m 0644 systemd/tunneld.service /etc/systemd/system/tunneld.service
sudo systemctl daemon-reload
sudo systemctl enable --now tunneld
sudo journalctl -u tunneld -f
```

From the gateway, verify that the daemon completed a WireGuard handshake and
that traffic reaches the client-side local service through the tunnel:

```sh
sudo wg show wg0
curl -H 'Host: app.example.internal' http://10.100.0.5/
dig @10.100.0.1 app.example.internal
```

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
