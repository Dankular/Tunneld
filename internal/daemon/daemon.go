// Package daemon wires together wgtun, ingress, proxy, and dnsupdate into
// the running tunneld process: bring the WireGuard tunnel up, start the
// configured listeners inside it, keep DNS records published, and shut
// everything down cleanly when told to.
package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	wgdevice "golang.zx2c4.com/wireguard/device"

	"github.com/Dankular/Tunneld/internal/config"
	"github.com/Dankular/Tunneld/internal/dnsupdate"
	"github.com/Dankular/Tunneld/internal/ingress"
	"github.com/Dankular/Tunneld/internal/proxy"
	"github.com/Dankular/Tunneld/internal/wgtun"
)

// handshakeStaleAfter is how long without a successful WireGuard handshake
// before the watchdog logs a warning. It's a fixed, generous bound rather
// than derived from persistent_keepalive, since a peer with keepalives
// disabled can still go a long time between handshakes under UDP's
// connectionless model without that meaning anything is actually wrong.
const handshakeStaleAfter = 3 * time.Minute

// Daemon is one running tunneld process.
type Daemon struct {
	cfg   *config.Config
	log   *slog.Logger
	rules ingress.Rules
}

// New validates cfg (it must already have passed config.Config.Validate)
// and compiles its ingress rules, returning a Daemon ready to Run.
func New(cfg *config.Config, log *slog.Logger) (*Daemon, error) {
	rules, err := ingress.Compile(cfg.Ingress)
	if err != nil {
		return nil, fmt.Errorf("daemon: %w", err)
	}
	return &Daemon{cfg: cfg, log: log, rules: rules}, nil
}

// Run brings the tunnel up and serves until ctx is cancelled, then shuts
// down cleanly. It returns nil on a clean shutdown, or the first fatal
// error encountered while serving.
func (d *Daemon) Run(ctx context.Context) error {
	wgLevel := wgdevice.LogLevelError
	if d.cfg.Log.Level == "debug" {
		wgLevel = wgdevice.LogLevelVerbose
	}

	wg, err := wgtun.Up(d.cfg, wgLevel)
	if err != nil {
		return fmt.Errorf("daemon: bring up WireGuard tunnel: %w", err)
	}
	defer wg.Close()
	d.log.Info("wireguard tunnel up", "address", wg.Self().String(), "peer_endpoint", d.cfg.WireGuard.Peer.Endpoint)

	listenIP := wg.Self()
	if d.cfg.HTTP.ListenAddr != "" {
		listenIP, err = netip.ParseAddr(d.cfg.HTTP.ListenAddr)
		if err != nil {
			return fmt.Errorf("daemon: http.listen_addr: %w", err)
		}
	}

	handler := proxy.NewHTTPHandler(d.rules, d.log)

	var wg2 sync.WaitGroup
	errCh := make(chan error, 8)
	var servers []*http.Server
	var tcpListeners []net.Listener

	startHTTPServer := func(name string, ln net.Listener, tlsConf *tls.Config) {
		srv := &http.Server{Handler: handler}
		if tlsConf != nil {
			srv.TLSConfig = tlsConf
		}
		servers = append(servers, srv)
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			var serveErr error
			if tlsConf != nil {
				serveErr = srv.Serve(tls.NewListener(ln, tlsConf))
			} else {
				serveErr = srv.Serve(ln)
			}
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				errCh <- fmt.Errorf("%s server: %w", name, serveErr)
			}
		}()
	}

	httpLn, err := wg.Net.ListenTCP(&net.TCPAddr{IP: listenIP.AsSlice(), Port: d.cfg.HTTP.ListenPort})
	if err != nil {
		return fmt.Errorf("daemon: listen on %s:%d inside tunnel: %w", listenIP, d.cfg.HTTP.ListenPort, err)
	}
	d.log.Info("http ingress listening", "addr", listenIP.String(), "port", d.cfg.HTTP.ListenPort)
	startHTTPServer("http", httpLn, nil)

	if d.cfg.HTTP.TLS.Enabled {
		tlsConf, err := proxy.BuildTLSConfig(d.cfg.HTTP.TLS.Certs)
		if err != nil {
			return fmt.Errorf("daemon: %w", err)
		}
		tlsLn, err := wg.Net.ListenTCP(&net.TCPAddr{IP: listenIP.AsSlice(), Port: d.cfg.HTTP.TLS.ListenPort})
		if err != nil {
			return fmt.Errorf("daemon: listen on %s:%d inside tunnel: %w", listenIP, d.cfg.HTTP.TLS.ListenPort, err)
		}
		d.log.Info("https ingress listening", "addr", listenIP.String(), "port", d.cfg.HTTP.TLS.ListenPort)
		startHTTPServer("https", tlsLn, tlsConf)
	}

	for _, rule := range d.rules.TCPRules() {
		ln, err := wg.Net.ListenTCP(&net.TCPAddr{IP: listenIP.AsSlice(), Port: rule.ListenPort})
		if err != nil {
			return fmt.Errorf("daemon: listen on %s:%d inside tunnel for %s: %w", listenIP, rule.ListenPort, rule.TargetAddr, err)
		}
		tcpListeners = append(tcpListeners, ln)
		d.log.Info("tcp ingress listening", "addr", listenIP.String(), "port", rule.ListenPort, "target", rule.TargetAddr)
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			if err := proxy.ServeTCP(ctx, ln, rule.TargetAddr, d.log); err != nil {
				errCh <- fmt.Errorf("tcp proxy on port %d: %w", rule.ListenPort, err)
			}
		}()
	}

	var dnsClient *dnsupdate.Client
	if d.cfg.DNS.Enabled {
		dnsClient, err = dnsupdate.New(dnsupdate.Config{
			Server:    d.cfg.DNS.Server,
			Zone:      d.cfg.DNS.Zone,
			KeyName:   d.cfg.DNS.TSIG.KeyName,
			Algorithm: d.cfg.DNS.TSIG.Algorithm,
			Secret:    d.cfg.DNS.TSIG.Secret,
			TTL:       uint32(d.cfg.DNS.TTL),
		})
		if err != nil {
			return fmt.Errorf("daemon: %w", err)
		}
		d.registerDNS(dnsClient, wg.Self())
		if d.cfg.DNS.RefreshInterval > 0 {
			wg2.Add(1)
			go func() {
				defer wg2.Done()
				d.dnsRefreshLoop(ctx, dnsClient, wg.Self())
			}()
		}
	}

	wg2.Add(1)
	go func() {
		defer wg2.Done()
		d.handshakeWatchdog(ctx, wg)
	}()

	select {
	case <-ctx.Done():
		d.log.Info("shutting down")
	case err := <-errCh:
		d.log.Error("fatal error, shutting down", "error", err)
		d.shutdownServers(servers, tcpListeners)
		if d.cfg.DNS.Enabled && d.cfg.DNS.DeregisterOnExit {
			d.deregisterDNS(dnsClient)
		}
		wg2.Wait()
		return err
	}

	d.shutdownServers(servers, tcpListeners)
	if d.cfg.DNS.Enabled && d.cfg.DNS.DeregisterOnExit {
		d.deregisterDNS(dnsClient)
	}
	wg2.Wait()
	return nil
}

func (d *Daemon) shutdownServers(servers []*http.Server, tcpListeners []net.Listener) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			d.log.Warn("error shutting down http server", "error", err)
		}
	}
	for _, ln := range tcpListeners {
		_ = ln.Close()
	}
}

func (d *Daemon) registerDNS(c *dnsupdate.Client, addr netip.Addr) {
	for _, host := range d.rules.Hostnames() {
		if err := c.Upsert(host, addr); err != nil {
			d.log.Error("dns registration failed", "hostname", host, "error", err)
			continue
		}
		d.log.Info("dns record published", "hostname", host, "address", addr.String())
	}
}

func (d *Daemon) deregisterDNS(c *dnsupdate.Client) {
	for _, host := range d.rules.Hostnames() {
		if err := c.Delete(host); err != nil {
			d.log.Warn("dns deregistration failed", "hostname", host, "error", err)
			continue
		}
		d.log.Info("dns record removed", "hostname", host)
	}
}

func (d *Daemon) dnsRefreshLoop(ctx context.Context, c *dnsupdate.Client, addr netip.Addr) {
	ticker := time.NewTicker(d.cfg.DNS.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.registerDNS(c, addr)
		}
	}
}

// handshakeWatchdog periodically logs this node's WireGuard peer status.
// WireGuard's handshake is automatic and connectionless (UDP) - this is a
// monitor only, not a reconnect: wireguard-go itself decides when to
// re-handshake, and nothing here intervenes in that.
func (d *Daemon) handshakeWatchdog(ctx context.Context, wg *wgtun.Device) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			peers, err := wg.Status()
			if err != nil {
				d.log.Warn("failed to read wireguard status", "error", err)
				continue
			}
			for _, p := range peers {
				if !p.HasHandshake {
					d.log.Warn("wireguard peer has never completed a handshake", "endpoint", p.Endpoint)
					continue
				}
				if age := time.Since(p.LastHandshake); age > handshakeStaleAfter {
					d.log.Warn("wireguard peer handshake is stale", "endpoint", p.Endpoint, "age", age.Round(time.Second))
				}
			}
		}
	}
}
