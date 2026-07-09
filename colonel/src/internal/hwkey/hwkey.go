// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hwkey is JanOS's unified hardware-key layer: one entry
// point that hands back whatever hardware root of trust the machine
// exposes, so identity code can ask for a hardware-backed key without
// caring whether it comes from a TPM, a Secure Enclave, or (later)
// Pluton via CNG.
//
// This is the "roll with whatever the system exposes" seam.  The
// per-platform providers already present the same shape —
// internal/tpm2 (Linux/Windows) and internal/secureenclave (macOS)
// both generate a P-256 key whose private scalar never leaves the
// hardware and expose PublicPoint / Sign / ECDH / Close — so hwkey
// just selects the right one at build time and returns it behind a
// common interface.  All operations use JanOS's native formats:
// 64-byte uncompressed X||Y public points, raw r||s signatures over a
// 32-byte SHA-256 digest, 32-byte ECDH shared X.
//
// The identity layer opens one Provider per process and mints an
// identity key per spark; the scalar stays in hardware, so Derive
// becomes the key's ECDH and attestation becomes its Sign.
package hwkey

import "errors"

// ErrUnavailable is returned by Open when no hardware root of trust is
// present or usable on this platform.
var ErrUnavailable = errors.New("hwkey: no hardware root of trust available")

// Provider mints hardware-backed keys.  A process opens one and holds
// it for the lifetime of the hardware session.
type Provider interface {
	// GenerateKey mints a fresh P-256 key whose private scalar is
	// generated in the hardware and never leaves it.
	GenerateKey() (Key, error)
	// Close releases the provider's hardware session.
	Close() error
}

// Key is a hardware-backed P-256 key.  The private scalar lives in the
// hardware; only the public point and operation results cross out.
type Key interface {
	// PublicPoint returns the 64-byte uncompressed X||Y public point.
	PublicPoint() ([64]byte, error)
	// Sign returns a raw r||s ECDSA signature (64 bytes) over a
	// 32-byte SHA-256 digest, computed in the hardware.
	Sign(digest []byte) ([]byte, error)
	// ECDH returns the 32-byte shared X coordinate of this key and a
	// peer's public point, computed in the hardware.
	ECDH(peer [64]byte) ([]byte, error)
	// Close releases the key.
	Close() error
}
