package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
)

// ServeTCP accepts connections on ln and proxies each, byte for byte, to
// targetAddr, until ctx is cancelled or ln is closed. It blocks until the
// accept loop exits and returns nil on a clean shutdown (ln closed, or ctx
// cancelled), or the Accept error otherwise.
func ServeTCP(ctx context.Context, ln net.Listener, targetAddr string, log *slog.Logger) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var dialer net.Dialer
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		go proxyTCPConn(ctx, conn, targetAddr, &dialer, log)
	}
}

func proxyTCPConn(ctx context.Context, conn net.Conn, targetAddr string, dialer *net.Dialer, log *slog.Logger) {
	defer conn.Close()

	target, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		log.Warn("tcp proxy: failed to dial local target", "target", targetAddr, "error", err)
		return
	}
	defer target.Close()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(target, conn)
		if c, ok := target.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, target)
		if c, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}
