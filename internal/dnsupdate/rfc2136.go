// Package dnsupdate publishes this node's WireGuard address into an
// authoritative DNS server via RFC 2136 dynamic updates, TSIG-signed
// (RFC 2845), using github.com/miekg/dns.
//
// The library calls used here (Msg.SetUpdate, Msg.RemoveRRset, Msg.Insert,
// Msg.SetTsig, Client.Exchange with Client.TsigSecret) and the TSIG
// algorithm name constants (dns.HmacSHA256 etc., which are the literal
// strings "hmac-sha256." and so on) were verified against
// github.com/miekg/dns's update.go, defaults.go, client.go and tsig.go
// source, not assumed from nsupdate familiarity.
package dnsupdate

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// Config configures one RFC 2136 dynamic DNS client.
type Config struct {
	// Server is host:port of the authoritative DNS server; port defaults
	// to 53 if omitted.
	Server string
	// Zone is the zone the UPDATE is issued against, e.g. "example.internal."
	Zone string
	// KeyName, Algorithm (e.g. "hmac-sha256."), and Secret (base64) are
	// the TSIG credentials authenticating the update.
	KeyName   string
	Algorithm string
	Secret    string
	// TTL applied to records this client writes.
	TTL uint32
	// Net is "udp" or "tcp"; empty defaults to "udp" (nsupdate's default).
	Net string
	// Timeout bounds each exchange; defaults to 5s if zero.
	Timeout time.Duration
}

// Client issues RFC 2136 updates for one zone.
type Client struct {
	cfg     Config
	server  string
	keyName string
}

// New validates cfg and returns a ready Client.
func New(cfg Config) (*Client, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("dnsupdate: server is required")
	}
	if cfg.Zone == "" {
		return nil, fmt.Errorf("dnsupdate: zone is required")
	}
	if cfg.KeyName == "" || cfg.Secret == "" {
		return nil, fmt.Errorf("dnsupdate: tsig key_name and secret are required")
	}

	server := cfg.Server
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}

	algo := cfg.Algorithm
	if algo == "" {
		algo = dns.HmacSHA256
	} else if algo[len(algo)-1] != '.' {
		algo += "."
	}
	cfg.Algorithm = algo
	cfg.Zone = dns.Fqdn(cfg.Zone)
	if cfg.Net == "" {
		cfg.Net = "udp"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}

	return &Client{
		cfg:     cfg,
		server:  server,
		keyName: dns.Fqdn(cfg.KeyName),
	}, nil
}

// Upsert replaces every existing A/AAAA record at hostname with a single
// record pointing at addr (RFC 2136 section 2.5.2 RemoveRRset, followed by
// section 2.5.1 Insert, in one UPDATE message).
func (c *Client) Upsert(hostname string, addr netip.Addr) error {
	fqdn := dns.Fqdn(hostname)

	var rr dns.RR
	var rrtype uint16
	if addr.Is4() {
		rrtype = dns.TypeA
		rr = &dns.A{
			Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: c.cfg.TTL},
			A:   net.IP(addr.AsSlice()),
		}
	} else {
		rrtype = dns.TypeAAAA
		rr = &dns.AAAA{
			Hdr:  dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: c.cfg.TTL},
			AAAA: net.IP(addr.AsSlice()),
		}
	}

	m := new(dns.Msg)
	m.SetUpdate(c.cfg.Zone)
	// RemoveRRset (verified in miekg/dns's update.go) only reads
	// r.Header() off each RR to build the "RRset does not exist"
	// prerequisite-clearing record, so a zero-value record of the right
	// type with just Hdr set is sufficient here.
	m.RemoveRRset([]dns.RR{headerOnlyRR(fqdn, rrtype)})
	m.Insert([]dns.RR{rr})

	return c.exchange(m)
}

// Delete removes every A and AAAA record at hostname.
func (c *Client) Delete(hostname string) error {
	fqdn := dns.Fqdn(hostname)
	m := new(dns.Msg)
	m.SetUpdate(c.cfg.Zone)
	m.RemoveRRset([]dns.RR{
		headerOnlyRR(fqdn, dns.TypeA),
		headerOnlyRR(fqdn, dns.TypeAAAA),
	})
	return c.exchange(m)
}

// headerOnlyRR builds a real dns.A/dns.AAAA record with nothing but its
// header set, for use where only RR.Header() is read (RemoveRRset).
func headerOnlyRR(fqdn string, rrtype uint16) dns.RR {
	hdr := dns.RR_Header{Name: fqdn, Rrtype: rrtype, Class: dns.ClassINET}
	if rrtype == dns.TypeAAAA {
		return &dns.AAAA{Hdr: hdr}
	}
	return &dns.A{Hdr: hdr}
}

func (c *Client) exchange(m *dns.Msg) error {
	m.SetTsig(c.keyName, c.cfg.Algorithm, 300, time.Now().Unix())

	client := new(dns.Client)
	client.Net = c.cfg.Net
	client.Timeout = c.cfg.Timeout
	client.TsigSecret = map[string]string{c.keyName: c.cfg.Secret}

	r, _, err := client.Exchange(m, c.server)
	if err != nil {
		return fmt.Errorf("dnsupdate: exchange with %s: %w", c.server, err)
	}
	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("dnsupdate: %s rejected update: %s", c.server, dns.RcodeToString[r.Rcode])
	}
	return nil
}
