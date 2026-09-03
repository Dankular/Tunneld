package ingress

import (
	"testing"

	"github.com/Dankular/Tunneld/internal/config"
)

func TestCompileAndMatchHTTP(t *testing.T) {
	rules, err := Compile([]config.Ingress{
		{Hostname: "app.example.internal", Service: "http://127.0.0.1:8080"},
		{Service: "http_status:404"},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	r, ok := rules.Match("app.example.internal", "/")
	if !ok {
		t.Fatal("expected match")
	}
	if r.Kind != KindHTTP || r.TargetURL.String() != "http://127.0.0.1:8080" {
		t.Errorf("unexpected rule: %+v", r)
	}

	// Host header with a port should still match.
	r2, ok := rules.Match("app.example.internal:443", "/")
	if !ok || r2.Kind != KindHTTP {
		t.Errorf("expected port-suffixed host to match, got %+v ok=%v", r2, ok)
	}

	// Case-insensitive.
	r3, ok := rules.Match("APP.EXAMPLE.INTERNAL", "/")
	if !ok || r3.Kind != KindHTTP {
		t.Errorf("expected case-insensitive match, got %+v ok=%v", r3, ok)
	}
}

func TestCompileAndMatchCatchAll(t *testing.T) {
	rules, err := Compile([]config.Ingress{
		{Hostname: "app.example.internal", Service: "http://127.0.0.1:8080"},
		{Service: "http_status:404"},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	r, ok := rules.Match("unknown.example.internal", "/")
	if !ok {
		t.Fatal("expected catch-all match")
	}
	if r.Kind != KindStatus || r.StatusCode != 404 {
		t.Errorf("unexpected catch-all rule: %+v", r)
	}
}

func TestMatchPathRegex(t *testing.T) {
	rules, err := Compile([]config.Ingress{
		{Hostname: "app.example.internal", PathRegex: "^/api/.*", Service: "http://127.0.0.1:9000"},
		{Hostname: "app.example.internal", Service: "http://127.0.0.1:8080"},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	r, ok := rules.Match("app.example.internal", "/api/widgets")
	if !ok || r.TargetURL.Port() != "9000" {
		t.Errorf("expected /api/ to route to :9000, got %+v ok=%v", r, ok)
	}

	r2, ok := rules.Match("app.example.internal", "/home")
	if !ok || r2.TargetURL.Port() != "8080" {
		t.Errorf("expected /home to fall through to :8080, got %+v ok=%v", r2, ok)
	}
}

func TestCompileTCPRule(t *testing.T) {
	rules, err := Compile([]config.Ingress{
		{Hostname: "ssh.example.internal", Service: "tcp://127.0.0.1:22", ListenPort: 2222},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	tcp := rules.TCPRules()
	if len(tcp) != 1 || tcp[0].TargetAddr != "127.0.0.1:22" || tcp[0].ListenPort != 2222 {
		t.Errorf("unexpected TCP rules: %+v", tcp)
	}
}

func TestCompileRejectsUnknownScheme(t *testing.T) {
	_, err := Compile([]config.Ingress{
		{Hostname: "app.example.internal", Service: "ftp://127.0.0.1"},
	})
	if err == nil {
		t.Error("expected error for unknown scheme")
	}
}

func TestNoMatchWithoutCatchAll(t *testing.T) {
	rules, err := Compile([]config.Ingress{
		{Hostname: "app.example.internal", Service: "http://127.0.0.1:8080"},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	_, ok := rules.Match("other.example.internal", "/")
	if ok {
		t.Error("expected no match without catch-all rule")
	}
}

func TestHostnames(t *testing.T) {
	rules, err := Compile([]config.Ingress{
		{Hostname: "a.example.internal", Service: "http://127.0.0.1:1"},
		{Hostname: "b.example.internal", Service: "http://127.0.0.1:2"},
		{Hostname: "a.example.internal", PathRegex: "^/x", Service: "http://127.0.0.1:3"},
		{Service: "http_status:404"},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	got := rules.Hostnames()
	want := []string{"a.example.internal", "b.example.internal"}
	if len(got) != len(want) {
		t.Fatalf("Hostnames() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Hostnames()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
