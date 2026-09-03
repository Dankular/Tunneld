package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Dankular/Tunneld/internal/config"
	"github.com/Dankular/Tunneld/internal/ingress"
)

func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestHTTPHandlerRoutesByHost(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello from backend")
	}))
	defer backend.Close()

	rules, err := ingress.Compile([]config.Ingress{
		{Hostname: "app.example.internal", Service: backend.URL},
		{Service: "http_status:404"},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	h := NewHTTPHandler(rules, testLogger())

	req := httptest.NewRequest(http.MethodGet, "http://app.example.internal/", nil)
	req.Host = "app.example.internal"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "hello from backend" {
		t.Errorf("body = %q, want %q", got, "hello from backend")
	}
}

func TestHTTPHandlerCatchAllStatus(t *testing.T) {
	rules, err := ingress.Compile([]config.Ingress{
		{Hostname: "app.example.internal", Service: "http://127.0.0.1:1"},
		{Service: "http_status:404"},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	h := NewHTTPHandler(rules, testLogger())

	req := httptest.NewRequest(http.MethodGet, "http://unknown.example.internal/", nil)
	req.Host = "unknown.example.internal"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestHTTPHandlerNoMatchWithoutCatchAll(t *testing.T) {
	rules, err := ingress.Compile([]config.Ingress{
		{Hostname: "app.example.internal", Service: "http://127.0.0.1:1"},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	h := NewHTTPHandler(rules, testLogger())

	req := httptest.NewRequest(http.MethodGet, "http://unknown.example.internal/", nil)
	req.Host = "unknown.example.internal"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestBuildTLSConfigMissingFiles(t *testing.T) {
	_, err := BuildTLSConfig([]config.CertPair{
		{Hostname: "app.example.internal", CertFile: "/nonexistent/cert.pem", KeyFile: "/nonexistent/key.pem"},
	})
	if err == nil {
		t.Error("expected error for missing cert files")
	}
}
