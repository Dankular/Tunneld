package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tunneld.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

const validConfig = `
wireguard:
  private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  address: "10.100.0.5/32"
  peer:
    public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
    endpoint: "gateway.example.com:51820"
    allowed_ips: ["10.100.0.0/16"]
    persistent_keepalive: 25

dns:
  enabled: true
  server: "10.100.0.1:53"
  zone: "example.internal."
  tsig:
    key_name: "tunneld-key."
    algorithm: "hmac-sha256"
    secret: "c2VjcmV0"

ingress:
  - hostname: "app.example.internal"
    service: "http://127.0.0.1:8080"
  - service: "http_status:404"
`

func TestLoadValid(t *testing.T) {
	path := writeTemp(t, validConfig)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.WireGuard.MTU != 1420 {
		t.Errorf("MTU default = %d, want 1420", c.WireGuard.MTU)
	}
	if c.HTTP.ListenPort != 80 {
		t.Errorf("HTTP.ListenPort default = %d, want 80", c.HTTP.ListenPort)
	}
	if c.DNS.TTL != 60 {
		t.Errorf("DNS.TTL default = %d, want 60", c.DNS.TTL)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/tunneld.yaml"); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadUnknownField(t *testing.T) {
	path := writeTemp(t, validConfig+"\nbogus_field: true\n")
	if _, err := Load(path); err == nil {
		t.Error("expected error for unknown field")
	}
}

func TestValidateCatchAllMustBeLast(t *testing.T) {
	c := &Config{
		WireGuard: WireGuard{
			PrivateKey: "x",
			Address:    "10.100.0.5/32",
			Peer: Peer{
				PublicKey:  "y",
				Endpoint:   "gw:51820",
				AllowedIPs: []string{"10.100.0.0/16"},
			},
		},
		Ingress: []Ingress{
			{Service: "http_status:404"},
			{Hostname: "app.example.internal", Service: "http://127.0.0.1:8080"},
		},
	}
	c.applyDefaults()
	if err := c.Validate(); err == nil {
		t.Error("expected error when catch-all rule is not last")
	}
}

func TestValidateTCPRequiresListenPort(t *testing.T) {
	c := &Config{
		WireGuard: WireGuard{
			PrivateKey: "x",
			Address:    "10.100.0.5/32",
			Peer: Peer{
				PublicKey:  "y",
				Endpoint:   "gw:51820",
				AllowedIPs: []string{"10.100.0.0/16"},
			},
		},
		Ingress: []Ingress{
			{Hostname: "ssh.example.internal", Service: "tcp://127.0.0.1:22"},
		},
	}
	c.applyDefaults()
	if err := c.Validate(); err == nil {
		t.Error("expected error for tcp:// service without listen_port")
	}
}

func TestValidateRejectsBadCIDR(t *testing.T) {
	c := &Config{
		WireGuard: WireGuard{
			PrivateKey: "x",
			Address:    "not-a-cidr",
			Peer: Peer{
				PublicKey:  "y",
				Endpoint:   "gw:51820",
				AllowedIPs: []string{"10.100.0.0/16"},
			},
		},
		Ingress: []Ingress{{Service: "http_status:404"}},
	}
	c.applyDefaults()
	if err := c.Validate(); err == nil {
		t.Error("expected error for invalid wireguard.address")
	}
}

func TestValidateRejectsUnknownServiceScheme(t *testing.T) {
	c := &Config{
		WireGuard: WireGuard{
			PrivateKey: "x",
			Address:    "10.100.0.5/32",
			Peer: Peer{
				PublicKey:  "y",
				Endpoint:   "gw:51820",
				AllowedIPs: []string{"10.100.0.0/16"},
			},
		},
		Ingress: []Ingress{{Hostname: "app.example.internal", Service: "ftp://127.0.0.1"}},
	}
	c.applyDefaults()
	if err := c.Validate(); err == nil {
		t.Error("expected error for unsupported service scheme")
	}
}

func TestValidateDNSRequiresTSIGWhenEnabled(t *testing.T) {
	c := &Config{
		WireGuard: WireGuard{
			PrivateKey: "x",
			Address:    "10.100.0.5/32",
			Peer: Peer{
				PublicKey:  "y",
				Endpoint:   "gw:51820",
				AllowedIPs: []string{"10.100.0.0/16"},
			},
		},
		DNS: DNS{
			Enabled: true,
			Server:  "10.100.0.1:53",
			Zone:    "example.internal.",
		},
		Ingress: []Ingress{{Service: "http_status:404"}},
	}
	c.applyDefaults()
	if err := c.Validate(); err == nil {
		t.Error("expected error when dns.enabled but tsig missing")
	}
}
