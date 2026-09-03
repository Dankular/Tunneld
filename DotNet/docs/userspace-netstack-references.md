# Userspace Netstack References

The .NET daemon target is a managed replacement for the Go daemon's
userspace WireGuard and TCP/IP path. These references are design inputs only.
Do not bind to QEMU, libslirp, passt, gVisor, Wintun, or WireGuardNT from the
.NET runtime.

## Parity Target

The Go daemon remains the behavior target. It uses WireGuard in userspace with
gVisor netstack, so the .NET runtime needs the same shape:

- encrypted WireGuard packets enter and leave over UDP
- decrypted IP packets are routed inside the process
- TCP listeners exist on the node's virtual tunnel IPs
- accepted streams are bridged to the existing HTTP, TLS, and TCP proxy logic

The current C# runner is not that yet. It is a host-network runner plus an
`IO.NET.TCPIP` loopback POC. `IO.NET.TCPIP` exposes client/server helpers over
normal host TCP sockets, so it is useful only as a smoke test boundary.

## QEMU And libslirp

QEMU's `-net user` mode is the most useful architecture reference for the
event-loop boundary. QEMU feeds packets into libslirp with `slirp_input(...)`
and gives libslirp callbacks for packet egress, timers, poll registration,
socket registration, and wakeups. That is the same boundary we need in managed
C#: packet in, packet out, explicit timers, and a single observable connection
table.

Reference files:

- QEMU user networking docs:
  `https://www.qemu.org/docs/master/system/devices/net.html`
- QEMU libslirp adapter:
  `https://github.com/qemu/qemu/blob/master/net/slirp.c`
- libslirp upstream:
  `https://qemu.googlesource.com/libslirp/`
- libslirp TCP input state machine:
  `https://gitlab.com/qemu-project/libslirp/-/blob/master/src/tcp_input.c`
- libslirp TCP output path:
  `https://gitlab.com/qemu-project/libslirp/-/blob/master/src/tcp_output.c`
- libslirp socket bridge:
  `https://gitlab.com/qemu-project/libslirp/-/blob/master/src/socket.c`

Pieces to mirror conceptually:

- `slirp_input` style packet ingress into the stack
- callback-driven packet egress instead of direct device writes
- timer-owned retransmit, persist, keepalive, and TIME-WAIT handling
- poll or event-loop integration isolated from protocol code
- host forwarding and connection-info concepts for the provisioner dashboard

Pieces not to copy directly:

- QEMU's NAT-first topology. Tunneld primarily needs inbound virtual-IP
  listeners from a WireGuard gateway to local services.
- QEMU's external library boundary. The .NET daemon should keep this inside
  managed code unless we intentionally change the no-binding requirement.
- passt's daemon/socket model. It is useful as a modern user networking
  reference, but it is still an external dependency model.

## Other TCP/IP References

- `google/gvisor`: current Go userspace stack family and the closest behavior
  reference for the existing daemon.
- `google/netstack`: older standalone Go netstack, now superseded by gVisor.
- `netduino/Netduino.IP`: real C# TCP/IP stack structure, but old and tightly
  coupled to .NET Micro Framework and embedded interfaces.
- `dotpcap/packetnet`: packet parse/build helper, not a TCP state machine.
- `rustp2p/tcp_ip` and `narrowlink/ipstack`: useful Rust references for TUN
  stack layout and TCP conformance tests.

## Implementation Milestones

1. Add managed packet codecs for IPv4, IPv6, ICMP, UDP, TCP, and checksums.
2. Build a managed TCP listener state machine: SYN/SYN-ACK/ACK, payload ACKs,
   retransmit timers, FIN/RST, receive reassembly, send windows, and backoff.
3. Expose accepted virtual TCP connections as stream-like objects consumed by
   the existing HTTP, TLS, and raw TCP proxy code.
4. Add managed WireGuard transport: Noise IK handshake, session timers,
   keepalives, replay protection, allowed-IP routing, and UDP transport.
5. Add parity tests against the Go daemon behavior and an independent
   WireGuard peer so tunnel reachability is proven without host network
   interfaces.
