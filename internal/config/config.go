// Package config defines Tunneld's on-disk YAML configuration schema and
// validates it.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root of a tunneld.yaml file.
type Config struct {
	WireGuard WireGuard `yaml:"wireguard"`
	DNS       DNS       `yaml:"dns"`
	Ingress   []Ingress `yaml:"ingress"`
	HTTP      HTTP      `yaml:"http"`
	Log       Log       `yaml:"log"`
}

// WireGuard configures this node's WireGuard identity, interface, and its
// single peer (the gateway into your network).
type WireGuard struct {
	// PrivateKey is this node's WireGuard private key, standard base64
	// (as produced by `wg genkey`, or `tunneld genkey`).
	PrivateKey string `yaml:"private_key"`
	// Address is this node's address inside the WireGuard network, in
	// CIDR form (e.g. "10.100.0.5/32").
	Address string `yaml:"address"`
	// DNS are resolvers the daemon's own internal userspace network
	// stack uses for outbound lookups it makes itself. This is separate
	// from the dns.* block below, which publishes this node's own
	// hostname into your DNS server.
	DNS []string `yaml:"dns"`
	// MTU defaults to 1420 (wireguard-go's own example default) if zero.
	MTU int `yaml:"mtu"`
	// ListenPort is the local UDP source port; 0 picks a random port.
	ListenPort int `yaml:"listen_port"`

	Peer Peer `yaml:"peer"`
}

// Peer describes the single remote WireGuard peer this daemon connects
// outbound to (your gateway).
type Peer struct {
	PublicKey  string   `yaml:"public_key"`
	Endpoint   string   `yaml:"endpoint"`
	AllowedIPs []string `yaml:"allowed_ips"`
	// PersistentKeepalive, in seconds, keeps NAT mappings open so the
	// gateway can keep reaching this node even though this node made
	// the only outbound connection. 0 disables it.
	PersistentKeepalive int `yaml:"persistent_keepalive"`
}

// DNS configures RFC 2136 dynamic DNS updates that publish this node's
// WireGuard address under each ingress hostname.
type DNS struct {
	Enabled bool `yaml:"enabled"`
	// Server is the authoritative DNS server's address, host:port
	// (port defaults to 53 if omitted).
	Server string `yaml:"server"`
	// Zone is the zone the UPDATE is sent for (must be a parent of every
	// ingress hostname), e.g. "example.internal."
	Zone string `yaml:"zone"`
	TSIG TSIG   `yaml:"tsig"`
	TTL  int    `yaml:"ttl"`
	// RefreshInterval re-sends the update on a timer so the record
	// self-heals if it's ever lost; 0 disables the timer (update once
	// at startup only).
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	// RecordType is "A" or "AAAA"; if empty it's inferred from
	// wireguard.address's family.
	RecordType string `yaml:"record_type"`
	// DeregisterOnExit removes the records this node added on a clean
	// shutdown (SIGINT/SIGTERM). Off by default: a crash or an unclean
	// stop would otherwise leave the hostname resolving nowhere until
	// the next start.
	DeregisterOnExit bool `yaml:"deregister_on_exit"`
}

// TSIG holds the RFC 2845 signing key used to authenticate DNS updates.
type TSIG struct {
	// KeyName is the TSIG key name, FQDN form (e.g. "tunneld-key.").
	KeyName string `yaml:"key_name"`
	// Algorithm is one of the names miekg/dns's tsig package accepts,
	// e.g. "hmac-sha256." (a trailing dot is added if missing).
	Algorithm string `yaml:"algorithm"`
	// Secret is the base64-encoded shared secret, matching the value
	// nsupdate/dnssec-keygen produce.
	Secret string `yaml:"secret"`
}

// Ingress is one routing rule, modeled loosely on cloudflared's ingress
// rule list: an ordered list matched top to bottom, where a rule with no
// Hostname is a catch-all and must be last.
type Ingress struct {
	// Hostname this rule matches on (HTTP Host header / TLS SNI). Empty
	// means catch-all; only the last rule may leave this empty.
	Hostname string `yaml:"hostname"`
	// PathRegex optionally restricts the match to request paths matching
	// this regular expression.
	PathRegex string `yaml:"path"`
	// Service is either:
	//   - an http(s):// URL of a local service to reverse-proxy to, or
	//   - a tcp:// address of a local service to proxy at the TCP level
	//     (requires ListenPort), or
	//   - the literal "http_status:NNN" to always answer with that
	//     status code (typically used for the catch-all rule).
	Service string `yaml:"service"`
	// ListenPort is required for tcp:// services: the port on this
	// node's WireGuard interface to accept connections on.
	ListenPort int `yaml:"listen_port"`
}

// HTTP configures the reverse-proxy listeners bound on the WireGuard
// interface.
type HTTP struct {
	// ListenAddr is the address to bind inside the WireGuard netstack;
	// empty means "this node's own wireguard.address".
	ListenAddr string  `yaml:"listen_addr"`
	ListenPort int     `yaml:"listen_port"`
	TLS        HTTPTLS `yaml:"tls"`
}

// HTTPTLS optionally terminates TLS for configured hostnames via SNI.
type HTTPTLS struct {
	Enabled    bool       `yaml:"enabled"`
	ListenPort int        `yaml:"listen_port"`
	Certs      []CertPair `yaml:"certs"`
}

// CertPair is one SNI hostname's certificate and key file pair.
type CertPair struct {
	Hostname string `yaml:"hostname"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Log configures the daemon's structured logger.
type Log struct {
	// Level is one of "debug", "info", "warn", "error". Defaults to "info".
	Level string `yaml:"level"`
}

// Load reads and validates a config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.WireGuard.MTU == 0 {
		c.WireGuard.MTU = 1420
	}
	if c.DNS.TTL == 0 {
		c.DNS.TTL = 60
	}
	if c.HTTP.ListenPort == 0 {
		c.HTTP.ListenPort = 80
	}
	if c.HTTP.TLS.Enabled && c.HTTP.TLS.ListenPort == 0 {
		c.HTTP.TLS.ListenPort = 443
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
}

// Validate checks the config for internal consistency. It does not
// contact the network.
func (c *Config) Validate() error {
	var errs []string

	if c.WireGuard.PrivateKey == "" {
		errs = append(errs, "wireguard.private_key is required")
	}
	if c.WireGuard.Address == "" {
		errs = append(errs, "wireguard.address is required")
	} else if _, err := netip.ParsePrefix(c.WireGuard.Address); err != nil {
		errs = append(errs, fmt.Sprintf("wireguard.address: %v", err))
	}
	if c.WireGuard.Peer.PublicKey == "" {
		errs = append(errs, "wireguard.peer.public_key is required")
	}
	if c.WireGuard.Peer.Endpoint == "" {
		errs = append(errs, "wireguard.peer.endpoint is required")
	}
	if len(c.WireGuard.Peer.AllowedIPs) == 0 {
		errs = append(errs, "wireguard.peer.allowed_ips must have at least one entry")
	}
	for _, ip := range c.WireGuard.Peer.AllowedIPs {
		if _, err := netip.ParsePrefix(ip); err != nil {
			errs = append(errs, fmt.Sprintf("wireguard.peer.allowed_ips: %q: %v", ip, err))
		}
	}
	for _, s := range c.WireGuard.DNS {
		if _, err := netip.ParseAddr(s); err != nil {
			errs = append(errs, fmt.Sprintf("wireguard.dns: %q: %v", s, err))
		}
	}

	if c.DNS.Enabled {
		if c.DNS.Server == "" {
			errs = append(errs, "dns.server is required when dns.enabled is true")
		}
		if c.DNS.Zone == "" {
			errs = append(errs, "dns.zone is required when dns.enabled is true")
		}
		if c.DNS.TSIG.KeyName == "" || c.DNS.TSIG.Secret == "" {
			errs = append(errs, "dns.tsig.key_name and dns.tsig.secret are required when dns.enabled is true")
		}
		if rt := c.DNS.RecordType; rt != "" && rt != "A" && rt != "AAAA" {
			errs = append(errs, fmt.Sprintf("dns.record_type: must be A or AAAA, got %q", rt))
		}
	}

	if len(c.Ingress) == 0 {
		errs = append(errs, "ingress must have at least one rule")
	}
	for i, rule := range c.Ingress {
		last := i == len(c.Ingress)-1
		if rule.Hostname == "" && !last {
			errs = append(errs, fmt.Sprintf("ingress[%d]: only the last rule may omit hostname (catch-all)", i))
		}
		if rule.Service == "" {
			errs = append(errs, fmt.Sprintf("ingress[%d]: service is required", i))
			continue
		}
		switch {
		case strings.HasPrefix(rule.Service, "http://"), strings.HasPrefix(rule.Service, "https://"):
			// no further validation beyond the hostname check above.
		case strings.HasPrefix(rule.Service, "tcp://"):
			if rule.ListenPort == 0 {
				errs = append(errs, fmt.Sprintf("ingress[%d]: listen_port is required for tcp:// services", i))
			}
		case strings.HasPrefix(rule.Service, "http_status:"):
			// catch-all style fixed response; nothing further to validate.
		default:
			errs = append(errs, fmt.Sprintf("ingress[%d]: service %q must start with http://, https://, tcp://, or http_status:", i, rule.Service))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
