package wgkey

import "testing"

func TestGenerateIsClamped(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if k[0]&0x07 != 0 {
		t.Errorf("low 3 bits of byte 0 not cleared: %08b", k[0])
	}
	if k[31]&0x80 != 0 {
		t.Errorf("high bit of byte 31 not cleared: %08b", k[31])
	}
	if k[31]&0x40 == 0 {
		t.Errorf("bit 6 of byte 31 not set: %08b", k[31])
	}
}

func TestRoundTripBase64(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	s := k.String()
	got, err := ParseBase64(s)
	if err != nil {
		t.Fatalf("ParseBase64: %v", err)
	}
	if got != k {
		t.Errorf("round trip mismatch: got %x want %x", got, k)
	}
}

func TestHexLength(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(k.Hex()) != KeySize*2 {
		t.Errorf("hex length = %d, want %d", len(k.Hex()), KeySize*2)
	}
}

func TestParseBase64Invalid(t *testing.T) {
	if _, err := ParseBase64("not-valid-base64!!"); err == nil {
		t.Error("expected error for invalid base64")
	}
	// Valid base64 but wrong length.
	if _, err := ParseBase64("AAAA"); err == nil {
		t.Error("expected error for short key")
	}
}

func TestPublicDeterministic(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	p1 := k.Public()
	p2 := k.Public()
	if p1 != p2 {
		t.Error("Public() not deterministic")
	}
}
