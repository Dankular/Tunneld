// Package wgkey generates and encodes WireGuard Curve25519 keypairs.
//
// Key generation replicates the clamping wireguard-go itself applies in
// device.NoisePrivateKey.clamp() (golang.zx2c4.com/wireguard/device/noise-helpers.go):
// the standard X25519 clamp from RFC 7748 section 5. Public keys are derived
// with the same curve25519.ScalarBaseMult call wireguard-go uses.
//
// Keys are exchanged with the rest of this codebase as standard WireGuard
// base64 (the format produced by `wg genkey`/`wg pubkey`), since that's what
// operators already have in wg-quick configs. wireguard-go's UAPI, however,
// only accepts hex (verified against device/uapi.go: NoisePrivateKey.FromMaybeZeroHex
// and NoisePublicKey.FromHex both call loadExactHex, which hex-decodes), so
// wgtun converts base64 -> hex right before calling IpcSet.
package wgkey

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeySize is the size in bytes of a Curve25519 WireGuard key.
const KeySize = 32

// Key is a 32-byte WireGuard key (private or public).
type Key [KeySize]byte

// Generate creates a new random private key, clamped per RFC 7748 section 5,
// matching wireguard-go's NoisePrivateKey.clamp().
func Generate() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, fmt.Errorf("wgkey: generate: %w", err)
	}
	k.clamp()
	return k, nil
}

// clamp applies the standard X25519 clamp (RFC 7748 section 5), identical to
// wireguard-go's device.NoisePrivateKey.clamp().
func (k *Key) clamp() {
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
}

// Public derives the Curve25519 public key for a private key k.
func (k Key) Public() Key {
	var pub Key
	curve25519.ScalarBaseMult((*[KeySize]byte)(&pub), (*[KeySize]byte)(&k))
	return pub
}

// String returns the key in standard WireGuard base64 form (as produced by
// `wg genkey` / `wg pubkey`).
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// Hex returns the key hex-encoded, the form wireguard-go's UAPI (IpcSet)
// requires for private_key/public_key/preshared_key lines.
func (k Key) Hex() string {
	return hex.EncodeToString(k[:])
}

// ParseBase64 decodes a standard WireGuard base64 key (44 chars, as produced
// by `wg genkey`/`wg pubkey`).
func ParseBase64(s string) (Key, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("wgkey: invalid base64 key: %w", err)
	}
	if len(b) != KeySize {
		return Key{}, fmt.Errorf("wgkey: key must decode to %d bytes, got %d", KeySize, len(b))
	}
	var k Key
	copy(k[:], b)
	return k, nil
}
