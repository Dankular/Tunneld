package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// startEchoServer runs a TCP server that echoes back whatever it reads,
// until the test ends.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestServeTCPProxiesData(t *testing.T) {
	target := startEchoServer(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- ServeTCP(ctx, ln, target, testLogger()) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	want := "hello through the tunnel"
	if _, err := conn.Write([]byte(want)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if c, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = c.CloseWrite()
	}

	buf := make([]byte, len(want))
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echoed data: %v", err)
	}
	if string(buf) != want {
		t.Errorf("echoed = %q, want %q", buf, want)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("ServeTCP returned error after cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeTCP did not exit after context cancel")
	}
}

func TestServeTCPDialFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	// Port 1 on loopback should reliably refuse connections.
	go func() { errCh <- ServeTCP(ctx, ln, "127.0.0.1:1", testLogger()) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// The proxied dial will fail; the client side should be closed.
	buf := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected connection to be closed after failed dial to target")
	}
	conn.Close()

	cancel()
	<-errCh
}
