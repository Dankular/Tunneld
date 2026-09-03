// Package proxy implements the two service kinds ingress rules can target:
// an HTTP(S) reverse proxy (http.go) and a raw TCP passthrough (tcp.go).
package proxy

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"

	"github.com/Dankular/Tunneld/internal/config"
	"github.com/Dankular/Tunneld/internal/ingress"
)

// HTTPHandler reverse-proxies incoming requests to the local service named
// by whichever ingress rule matches the request's Host header and path.
type HTTPHandler struct {
	rules   ingress.Rules
	log     *slog.Logger
	reverse map[string]*httputil.ReverseProxy // keyed by TargetURL.String()
}

// NewHTTPHandler builds an http.Handler for rules, pre-building one
// *httputil.ReverseProxy per distinct HTTP target so each request reuses
// it (and its connection pooling) instead of constructing one per request.
func NewHTTPHandler(rules ingress.Rules, log *slog.Logger) *HTTPHandler {
	h := &HTTPHandler{
		rules:   rules,
		log:     log,
		reverse: make(map[string]*httputil.ReverseProxy),
	}
	for _, r := range rules {
		if r.Kind != ingress.KindHTTP {
			continue
		}
		key := r.TargetURL.String()
		if _, ok := h.reverse[key]; ok {
			continue
		}
		h.reverse[key] = httputil.NewSingleHostReverseProxy(r.TargetURL)
	}
	return h
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rule, ok := h.rules.Match(r.Host, r.URL.Path)
	if !ok {
		http.Error(w, "tunneld: no ingress rule matches this hostname", http.StatusNotFound)
		return
	}

	switch rule.Kind {
	case ingress.KindStatus:
		w.WriteHeader(rule.StatusCode)

	case ingress.KindHTTP:
		rp, ok := h.reverse[rule.TargetURL.String()]
		if !ok {
			// Unreachable if NewHTTPHandler was built from the same
			// rules being matched against.
			http.Error(w, "tunneld: internal routing error", http.StatusBadGateway)
			return
		}
		rp.ServeHTTP(w, r)

	default:
		// A KindTCP rule reached the HTTP handler, which means it's
		// misconfigured to also be matched by Host header here -
		// TCP rules only listen on their own dedicated ListenPort.
		h.log.Warn("ingress rule matched HTTP request but is not an HTTP service",
			"hostname", rule.Hostname)
		http.Error(w, "tunneld: misconfigured ingress rule", http.StatusBadGateway)
	}
}

// BuildTLSConfig builds an SNI-dispatching *tls.Config from the configured
// cert/key pairs, so one TLS listener can terminate multiple hostnames.
func BuildTLSConfig(certs []config.CertPair) (*tls.Config, error) {
	byHost := make(map[string]tls.Certificate, len(certs))
	for _, c := range certs {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("proxy: load cert for %q: %w", c.Hostname, err)
		}
		byHost[c.Hostname] = cert
	}
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, ok := byHost[hello.ServerName]
			if !ok {
				return nil, fmt.Errorf("proxy: no certificate configured for SNI hostname %q", hello.ServerName)
			}
			return &cert, nil
		},
	}, nil
}
