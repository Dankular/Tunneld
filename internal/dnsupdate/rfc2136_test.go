package dnsupdate

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	testKeyName = "tunneld-key."
	testSecret  = "c2VjcmV0LXRlc3Qta2V5LWJhc2U2NA==" // arbitrary base64 test secret
)

// startFakeServer runs a minimal RFC2136 server on loopback that records
// the last UPDATE it received and always replies NOERROR, so tests can
// assert on exactly what the Client sent without depending on a real DNS
// server binary being installed.
func startFakeServer(t *testing.T, handler func(w dns.ResponseWriter, r *dns.Msg)) (addr string, shutdown func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	srv := &dns.Server{
		PacketConn: pc,
		Handler:    dns.HandlerFunc(handler),
		TsigSecret: map[string]string{testKeyName: testSecret},
		// miekg/dns's DefaultMsgAcceptFunc (acceptfunc.go) rejects any
		// Opcode other than Query/Notify as "not implemented" - RFC 2136
		// UPDATE messages need an accept func that allows OpcodeUpdate
		// too, confirmed by reading that source after a real fake-server
		// test came back NOTIMP.
		MsgAcceptFunc: acceptQueryNotifyUpdate,
	}

	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }

	go func() {
		_ = srv.ActivateAndServe()
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("fake DNS server did not start in time")
	}

	return pc.LocalAddr().String(), func() {
		_ = srv.Shutdown()
	}
}

// acceptQueryNotifyUpdate is dns.DefaultMsgAcceptFunc (acceptfunc.go) with
// OpcodeUpdate additionally allowed, and the prereq/update RR-count limits
// it applies to Query/Notify dropped for Update messages (an UPDATE
// legitimately carries many RRs in the prerequisite and update sections).
func acceptQueryNotifyUpdate(dh dns.Header) dns.MsgAcceptAction {
	const headerQR = 1 << 15 // RFC 1035 4.1.1: bit 15 of the header flags word.
	if dh.Bits&headerQR != 0 {
		return dns.MsgIgnore
	}
	opcode := int(dh.Bits>>11) & 0xF
	switch opcode {
	case dns.OpcodeQuery, dns.OpcodeNotify:
		if dh.Qdcount != 1 || dh.Ancount > 1 || dh.Nscount > 1 || dh.Arcount > 2 {
			return dns.MsgReject
		}
	case dns.OpcodeUpdate:
		if dh.Qdcount != 1 {
			return dns.MsgReject
		}
	default:
		return dns.MsgRejectNotImplemented
	}
	return dns.MsgAccept
}

func TestUpsertSendsSignedAUpdate(t *testing.T) {
	var gotOpcode int
	var gotZone string
	var gotTsigVerified error
	var gotInsertA string
	done := make(chan struct{}, 1)

	addr, shutdown := startFakeServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		gotOpcode = r.Opcode
		if len(r.Question) > 0 {
			gotZone = r.Question[0].Name
		}
		if tsig := r.IsTsig(); tsig != nil {
			gotTsigVerified = w.TsigStatus()
		}
		for _, rr := range r.Ns {
			if a, ok := rr.(*dns.A); ok {
				gotInsertA = a.A.String()
			}
		}

		m := new(dns.Msg)
		m.SetReply(r)
		if r.IsTsig() != nil {
			m.SetTsig(testKeyName, dns.HmacSHA256, 300, time.Now().Unix())
		}
		_ = w.WriteMsg(m)
		done <- struct{}{}
	})
	defer shutdown()

	c, err := New(Config{
		Server:    addr,
		Zone:      "example.internal.",
		KeyName:   testKeyName,
		Algorithm: dns.HmacSHA256,
		Secret:    testSecret,
		TTL:       60,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := c.Upsert("app.example.internal", netip.MustParseAddr("10.100.0.5")); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server never handled request")
	}

	if gotOpcode != dns.OpcodeUpdate {
		t.Errorf("Opcode = %d, want OpcodeUpdate (%d)", gotOpcode, dns.OpcodeUpdate)
	}
	if gotZone != "example.internal." {
		t.Errorf("zone = %q, want %q", gotZone, "example.internal.")
	}
	if gotTsigVerified != nil {
		t.Errorf("TSIG verification failed: %v", gotTsigVerified)
	}
	if gotInsertA != "10.100.0.5" {
		t.Errorf("inserted A record = %q, want %q", gotInsertA, "10.100.0.5")
	}
}

func TestUpsertRejectsBadRcode(t *testing.T) {
	addr, shutdown := startFakeServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		if r.IsTsig() != nil {
			m.SetTsig(testKeyName, dns.HmacSHA256, 300, time.Now().Unix())
		}
		_ = w.WriteMsg(m)
	})
	defer shutdown()

	c, err := New(Config{
		Server:    addr,
		Zone:      "example.internal.",
		KeyName:   testKeyName,
		Algorithm: dns.HmacSHA256,
		Secret:    testSecret,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := c.Upsert("app.example.internal", netip.MustParseAddr("10.100.0.5")); err == nil {
		t.Error("expected error on REFUSED response")
	}
}

func TestNewRequiresServerZoneAndTsig(t *testing.T) {
	cases := []Config{
		{Zone: "z.", KeyName: "k.", Secret: "s"},
		{Server: "1.2.3.4:53", KeyName: "k.", Secret: "s"},
		{Server: "1.2.3.4:53", Zone: "z."},
	}
	for i, cfg := range cases {
		if _, err := New(cfg); err == nil {
			t.Errorf("case %d: expected error, config: %+v", i, cfg)
		}
	}
}

func TestNewDefaultsPortAndAlgorithm(t *testing.T) {
	c, err := New(Config{
		Server:  "10.100.0.1",
		Zone:    "example.internal.",
		KeyName: "tunneld-key.",
		Secret:  testSecret,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.server != "10.100.0.1:53" {
		t.Errorf("server = %q, want %q", c.server, "10.100.0.1:53")
	}
	if c.cfg.Algorithm != dns.HmacSHA256 {
		t.Errorf("algorithm default = %q, want %q", c.cfg.Algorithm, dns.HmacSHA256)
	}
}
