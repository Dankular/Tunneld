package daemon

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	wgconn "golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/miekg/dns"

	"github.com/Dankular/Tunneld/internal/config"
	"github.com/Dankular/Tunneld/internal/wgkey"
)

const (
	testDNSKeyName = "tunneld-key."
	testDNSSecret  = "c2VjcmV0LXRlc3Qta2V5LWJhc2U2NA=="
)

// fakeGateway is a second, independent userspace WireGuard device built
// directly against golang.zx2c4.com/wireguard/device (bypassing this
// project's wgtun package, which only models a single-peer client), acting
// as the "gateway" side of the tunnel in end-to-end tests: it dials the
// node under test's internal address the same way a real gateway would
// forward traffic to it.
type fakeGateway struct {
	dev  *wgdevice.Device
	tnet *netstack.Net
	port uint16
}

// newFakeGateway configures its device with a fixed, pre-chosen listenPort
// rather than 0-for-ephemeral-then-discover-the-real-port. Discovering it
// via IpcGet's "listen_port=" line (device/uapi.go's IpcGetOperation,
// device.net.port) turns out not to work on an IPv6-less host: verified by
// reading conn/bind_std.go's StdNetBind.Open, the IPv4 bind succeeds and
// gets a real ephemeral port, but the immediately following IPv6 bind
// attempt fails with EAFNOSUPPORT and its zero-value port return
// overwrites the shared `port` local var before it's stored on the
// device - so device.net.port (and thus IpcGet) reports 0 even though the
// IPv4 socket is correctly bound. This doesn't affect the running tunnel
// (the IPv4 receive loop still starts), only introspection of the port -
// but it means this test can't rely on it, so it picks the port itself.
func newFakeGateway(t *testing.T, priv wgkey.Key, listenPort uint16, selfAddr netip.Addr, nodePub wgkey.Key, nodeAllowedIP string) *fakeGateway {
	t.Helper()

	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{selfAddr}, nil, 1420)
	if err != nil {
		t.Fatalf("create gateway netstack TUN: %v", err)
	}

	dev := wgdevice.NewDevice(tunDev, wgconn.NewDefaultBind(), wgdevice.NewLogger(wgdevice.LogLevelSilent, ""))
	t.Cleanup(dev.Close)

	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=%s\n",
		priv.Hex(), listenPort, nodePub.Hex(), nodeAllowedIP)
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatalf("configure gateway device: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("bring gateway device up: %v", err)
	}

	return &fakeGateway{dev: dev, tnet: tnet, port: listenPort}
}

// pickFreeUDPPort reserves an ephemeral UDP port on loopback and releases
// it immediately, for use as a fixed listen_port. Small TOCTOU race,
// acceptable for a test.
func pickFreeUDPPort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick free udp port: %v", err)
	}
	defer conn.Close()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

// dnsRecordStore records every A record a fake RFC2136 server observed, so
// the end-to-end test can assert on what daemon.registerDNS actually sent.
type dnsRecordStore struct {
	mu     sync.Mutex
	byHost map[string]string
}

// startFakeDNSServer runs a minimal RFC2136 server on loopback UDP,
// TSIG-secured with testDNSKeyName/testDNSSecret, that always accepts
// updates and records the inserted A record per hostname.
func startFakeDNSServer(t *testing.T) (addr string, shutdown func(), records *dnsRecordStore) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp for fake dns server: %v", err)
	}

	store := &dnsRecordStore{byHost: make(map[string]string)}

	srv := &dns.Server{
		PacketConn: pc,
		TsigSecret: map[string]string{testDNSKeyName: testDNSSecret},
		// See internal/dnsupdate/rfc2136_test.go's acceptQueryNotifyUpdate
		// doc comment: the library's DefaultMsgAcceptFunc rejects UPDATE
		// (Opcode 5) as not implemented unless overridden.
		MsgAcceptFunc: acceptQueryNotifyUpdate,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			for _, rr := range r.Ns {
				if a, ok := rr.(*dns.A); ok {
					store.mu.Lock()
					store.byHost[a.Hdr.Name] = a.A.String()
					store.mu.Unlock()
				}
			}
			m := new(dns.Msg)
			m.SetReply(r)
			if r.IsTsig() != nil {
				m.SetTsig(testDNSKeyName, dns.HmacSHA256, 300, time.Now().Unix())
			}
			_ = w.WriteMsg(m)
		}),
	}

	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("fake dns server did not start in time")
	}

	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }, store
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

// TestEndToEndTunnelProxiesHTTP builds a real node (via daemon.Run, which
// itself calls wgtun.Up) and a real, independent fake-gateway WireGuard
// device, performs an actual WireGuard handshake between them over
// loopback UDP, then dials the node's internal address from the gateway
// side's own netstack the way a real gateway would, and verifies the
// request is reverse-proxied to a local backend and the hostname's DNS
// record is published.
func TestEndToEndTunnelProxiesHTTP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello from origin")
	}))
	defer backend.Close()

	nodeKey, err := wgkey.Generate()
	if err != nil {
		t.Fatalf("generate node key: %v", err)
	}
	gwKey, err := wgkey.Generate()
	if err != nil {
		t.Fatalf("generate gateway key: %v", err)
	}
	gwSelfAddr := netip.MustParseAddr("10.200.0.1")
	nodeAddr := netip.MustParseAddr("10.200.0.5")
	gwPort := pickFreeUDPPort(t)

	gw := newFakeGateway(t, gwKey, gwPort, gwSelfAddr, nodeKey.Public(), nodeAddr.String()+"/32")

	dnsAddr, dnsShutdown, dnsRecords := startFakeDNSServer(t)
	defer dnsShutdown()

	cfg := &config.Config{
		WireGuard: config.WireGuard{
			PrivateKey: nodeKey.String(),
			Address:    nodeAddr.String() + "/32",
			MTU:        1420,
			Peer: config.Peer{
				PublicKey:           gwKey.Public().String(),
				Endpoint:            fmt.Sprintf("127.0.0.1:%d", gw.port),
				AllowedIPs:          []string{gwSelfAddr.String() + "/32"},
				PersistentKeepalive: 1,
			},
		},
		DNS: config.DNS{
			Enabled: true,
			Server:  dnsAddr,
			Zone:    "example.internal.",
			TSIG: config.TSIG{
				KeyName:   testDNSKeyName,
				Algorithm: "hmac-sha256.",
				Secret:    testDNSSecret,
			},
			TTL: 60,
		},
		Ingress: []config.Ingress{
			{Hostname: "app.example.internal", Service: backend.URL},
			{Service: "http_status:404"},
		},
		HTTP: config.HTTP{ListenPort: 8080},
		Log:  config.Log{Level: "error"},
	}

	d, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()

	// Dial the node's internal address from the gateway's own netstack,
	// exactly as a real gateway forwarding public traffic would. Retry
	// while the WireGuard handshake completes and the node's listener
	// comes up.
	var conn net.Conn
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		dialCtx, cancelDial := context.WithTimeout(context.Background(), 500*time.Millisecond)
		conn, err = gw.tnet.DialContextTCPAddrPort(dialCtx, netip.AddrPortFrom(nodeAddr, 8080))
		cancelDial()
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("gateway could not reach node over the tunnel after handshake retries: %v", err)
	}
	conn.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return gw.tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(nodeAddr, 8080))
			},
		},
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest(http.MethodGet, "http://app.example.internal/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("request through tunnel failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "hello from origin" {
		t.Errorf("body = %q, want %q", body, "hello from origin")
	}

	dnsRecords.mu.Lock()
	gotIP := dnsRecords.byHost["app.example.internal."]
	dnsRecords.mu.Unlock()
	if gotIP != nodeAddr.String() {
		t.Errorf("dns record for app.example.internal. = %q, want %q", gotIP, nodeAddr.String())
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Errorf("Run returned error after shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not shut down in time")
	}
}
