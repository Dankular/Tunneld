// Command tunneld is an outbound-only reverse proxy daemon: it dials out
// over WireGuard to your own gateway, publishes its hostnames into your
// own DNS server via RFC 2136, and reverse-proxies inbound requests to
// local services - the way cloudflared connects outbound to Cloudflare's
// edge, but to infrastructure you run yourself.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Dankular/Tunneld/internal/config"
	"github.com/Dankular/Tunneld/internal/daemon"
	"github.com/Dankular/Tunneld/internal/version"
	"github.com/Dankular/Tunneld/internal/wgkey"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "run":
		cmdRun(os.Args[2:])
	case "validate":
		cmdValidate(os.Args[2:])
	case "genkey":
		cmdGenkey(os.Args[2:])
	case "version":
		fmt.Println("tunneld", version.String())
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "tunneld: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `tunneld - outbound WireGuard reverse tunnel to your own network

Usage:
  tunneld run --config <path>       Bring the tunnel up and serve until stopped
  tunneld validate --config <path>  Validate a config file without connecting
  tunneld genkey                    Generate a new WireGuard keypair
  tunneld version                   Print the tunneld version

`)
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "/etc/tunneld/tunneld.yaml", "path to tunneld.yaml")
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tunneld: run:", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.Log.Level)

	d, err := daemon.New(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize daemon", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := d.Run(ctx); err != nil {
		logger.Error("tunneld exited with an error", "error", err)
		os.Exit(1)
	}
}

func cmdValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := fs.String("config", "/etc/tunneld/tunneld.yaml", "path to tunneld.yaml")
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tunneld: validate:", err)
		os.Exit(1)
	}
	fmt.Printf("tunneld: %s is valid (%d ingress rule(s))\n", *configPath, len(cfg.Ingress))
}

func cmdGenkey(args []string) {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	fs.Parse(args)

	k, err := wgkey.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, "tunneld: genkey:", err)
		os.Exit(1)
	}
	fmt.Println("PrivateKey:", k.String())
	fmt.Println("PublicKey: ", k.Public().String())
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
