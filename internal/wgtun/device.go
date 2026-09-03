// Package wgtun brings up an outbound-only WireGuard tunnel entirely in
// userspace (no OS TUN device, no root) using wireguard-go's netstack TUN
// (golang.zx2c4.com/wireguard/tun/netstack), and exposes the resulting
// virtual network so the rest of the daemon can Listen/Dial on it.
//
// The UAPI config keys used below (private_key, listen_port, public_key,
// endpoint, allowed_ip, persistent_keepalive_interval) and their required
// encodings were verified directly against
// golang.zx2c4.com/wireguard/device/uapi.go (handleDeviceLine /
// handlePeerLine) rather than assumed from the wg-quick config format.
package wgtun

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/Dankular/Tunneld/internal/config"
	"github.com/Dankular/Tunneld/internal/wgkey"
)

// Device wraps a userspace WireGuard device and its virtual network stack.
type Device struct {
	dev  *device.Device
	Net  *netstack.Net
	self netip.Addr
}

// Up parses cfg, brings up the userspace WireGuard interface and its single
// peer, and returns the running Device. Call Close when done.
func Up(cfg *config.Config, logLevel int) (*Device, error) {
	prefix, err := netip.ParsePrefix(cfg.WireGuard.Address)
	if err != nil {
		return nil, fmt.Errorf("wgtun: wireguard.address: %w", err)
	}
	self := prefix.Addr()

	dnsAddrs := make([]netip.Addr, 0, len(cfg.WireGuard.DNS))
	for _, s := range cfg.WireGuard.DNS {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("wgtun: wireguard.dns: %w", err)
		}
		dnsAddrs = append(dnsAddrs, addr)
	}

	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{self}, dnsAddrs, cfg.WireGuard.MTU)
	if err != nil {
		return nil, fmt.Errorf("wgtun: create netstack TUN: %w", err)
	}

	uapiConf, err := buildUAPIConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("wgtun: %w", err)
	}

	logger := device.NewLogger(logLevel, "tunneld: ")
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(uapiConf); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wgtun: configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wgtun: bring device up: %w", err)
	}

	return &Device{dev: dev, Net: tnet, self: self}, nil
}

// Self returns this node's address inside the WireGuard network.
func (d *Device) Self() netip.Addr {
	return d.self
}

// Close tears down the WireGuard device and its network stack.
func (d *Device) Close() {
	d.dev.Close()
}

// PeerStatus is this node's single peer's last known handshake and traffic
// counters, read from the live UAPI "get" operation
// (device.Device.IpcGet / IpcGetOperation).
type PeerStatus struct {
	PublicKey        string
	Endpoint         string
	LastHandshake    time.Time
	HasHandshake     bool
	TxBytes, RxBytes uint64
}

// Status returns the current status of this node's peer(s), parsed from
// IpcGet's output format (verified against device/uapi.go's
// IpcGetOperation, which emits exactly these "key=value" lines per peer:
// public_key, endpoint, last_handshake_time_sec, tx_bytes, rx_bytes).
func (d *Device) Status() ([]PeerStatus, error) {
	raw, err := d.dev.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("wgtun: IpcGet: %w", err)
	}

	var peers []PeerStatus
	var cur *PeerStatus
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			peers = append(peers, PeerStatus{PublicKey: value})
			cur = &peers[len(peers)-1]
		case "endpoint":
			if cur != nil {
				cur.Endpoint = value
			}
		case "last_handshake_time_sec":
			if cur == nil {
				continue
			}
			secs, err := strconv.ParseInt(value, 10, 64)
			if err == nil && secs > 0 {
				cur.LastHandshake = time.Unix(secs, 0)
				cur.HasHandshake = true
			}
		case "tx_bytes":
			if cur != nil {
				if n, err := strconv.ParseUint(value, 10, 64); err == nil {
					cur.TxBytes = n
				}
			}
		case "rx_bytes":
			if cur != nil {
				if n, err := strconv.ParseUint(value, 10, 64); err == nil {
					cur.RxBytes = n
				}
			}
		}
	}
	return peers, nil
}

// buildUAPIConfig renders cfg into the newline-delimited "key=value" UAPI
// configuration string that device.Device.IpcSet expects.
func buildUAPIConfig(cfg *config.Config) (string, error) {
	priv, err := wgkey.ParseBase64(cfg.WireGuard.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("wireguard.private_key: %w", err)
	}
	peerPub, err := wgkey.ParseBase64(cfg.WireGuard.Peer.PublicKey)
	if err != nil {
		return "", fmt.Errorf("wireguard.peer.public_key: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv.Hex())
	if cfg.WireGuard.ListenPort != 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", cfg.WireGuard.ListenPort)
	}
	fmt.Fprintf(&b, "public_key=%s\n", peerPub.Hex())
	fmt.Fprintf(&b, "endpoint=%s\n", cfg.WireGuard.Peer.Endpoint)
	for _, ip := range cfg.WireGuard.Peer.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
	}
	if cfg.WireGuard.Peer.PersistentKeepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", cfg.WireGuard.Peer.PersistentKeepalive)
	}
	return b.String(), nil
}
