// JanOS: certificate accessors surfaced through the runtime API.
//
// The runtime holds three process-wide certificate values populated
// at schedinit (once the cert-slot verification passes).  They are
// read by user code through GuildCert(), ReleaseCert(), and
// UserCert().  Provenance carries only the compact SHA-256
// identifiers (GuildCertID / ReleaseCertID) so per-goroutine state
// stays tight — the full certificate values are shared across all
// goroutines in the process.
//
// Byte layout of Certificate is intentionally identical to
// cmd/janos/certslot.Certificate so the diviner pass can copy
// directly between them without translation.

package runtime

// Certificate is a JanOS binary-signature slot entry surfaced through
// the runtime API.  Fields mirror cmd/janos/certslot.Certificate
// byte-for-byte so a //go:linkname bridge from schedinit can populate
// them without re-encoding.
type Certificate struct {
	// Level is one of certslot.LevelGuild / LevelRelease / LevelUser.
	Level uint8
	// RevokeEpoch is the signer's per-key revocation serial.
	RevokeEpoch uint32
	// SignerPubKey is the ECDSA P-256 public key that produced
	// Signature.  Uncompressed X || Y (no SEC1 tag), 64 bytes.
	SignerPubKey [64]byte
	// ParentCert is the parent level's ECDSA P-256 signature over
	// SHA-256(SignerPubKey), 64 bytes r || s.  Zero for Guild
	// (no parent).
	ParentCert [64]byte
	// Signature is the ECDSA P-256 signature over the binary's
	// SHA-256 digest (computed with the slot region zeroed), 64
	// bytes r || s.
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
// JANOSCRT slot has not yet been populated.
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
