// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// JanOS: certificate accessors surfaced through the runtime API.
//
// The runtime holds three process-wide certificate values populated
// at schedinit (once the cert-slot verification hook is wired in via
// linker signing).  They are read by user code through GuildCert(),
// ReleaseCert(), and UserCert().  Provenance carries only the compact
// SHA-256 identifiers (GuildCertID / ReleaseCertID) so per-goroutine
// state stays tight — the full certificate values are shared across
// all goroutines in the process.
//
// Byte layout of Certificate is intentionally identical to the
// internal/runtime/janos_cert.Certificate type so a future linkname
// hook can copy directly between them without translation.

package runtime

// Certificate is a JanOS binary-signature slot entry surfaced through
// the runtime API.  Fields mirror janos_cert.Certificate byte-for-byte
// so a //go:linkname bridge from schedinit can populate them without
// re-encoding.
type Certificate struct {
	// Level is one of janos_cert.LevelGuild / LevelRelease / LevelUser.
	Level uint8
	// RevokeEpoch is the signer's per-key revocation serial.
	RevokeEpoch uint32
	// SignerPubKey is the Ed25519 public key that produced Signature.
	SignerPubKey [32]byte
	// ParentCert is the parent level's Ed25519 signature over
	// SignerPubKey.  Zero for Guild (no parent).
	ParentCert [64]byte
	// Signature is the Ed25519 signature over the binary's SHA-256
	// digest with the slot region zeroed.
	Signature [64]byte
}

// Process-wide certificate storage.  Populated at schedinit if a
// JANOSCRT slot verified successfully; otherwise zero (dev builds
// before the linker signing pass exists).  Once set they never
// change for the lifetime of the process, so racy reads from
// arbitrary goroutines are safe.
var (
	janosGuildCert   Certificate
	janosReleaseCert Certificate
	janosUserCert    Certificate
	janosHasUserCert bool
)

// GuildCert returns the JanOS Guild certificate embedded in this
// binary.  Fields are all zero on platforms/builds where the
// JANOSCRT slot has not yet been populated (currently everywhere,
// until the linker signing pass lands).
func GuildCert() Certificate { return janosGuildCert }

// ReleaseCert returns the JanOS Release certificate embedded in this
// binary.  Fields are all zero on unpopulated builds.
func ReleaseCert() Certificate { return janosReleaseCert }

// UserCert returns the User (Glitter signet) certificate embedded in
// this binary, or the zero value and false if no user certificate is
// attached.  JanOS does not enforce the user certificate — Glitter
// consumers use it for identification and disclosure-based execution.
func UserCert() (Certificate, bool) {
	if !janosHasUserCert {
		return Certificate{}, false
	}
	return janosUserCert, true
}
