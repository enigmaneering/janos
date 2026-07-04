// Package diviner defines the interface every KMS-backed signing
// backend implements for the JanOS toolchain, plus a URL-scheme
// registry that lets cmd/link's diviner pass dispatch to the right
// implementation at build time.
//
// A "diviner" is JanOS's name for the signing pass — it reads a
// binary, discovers its identity (SHA-256 of the image with the
// JANOSCRT slot zeroed), and stamps a Guild + Release blessing over
// it via an HSM-backed KMS.  Callers never hold a private key; all
// diviner references are URLs naming a KMS resource, and
// authentication is delegated to the operator's KMS SDK
// environment.
//
// URL format:
//
//	gcpkms://projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY/cryptoKeyVersions/N
//	awskms://arn:aws:kms:REGION:ACCOUNT:key/KEY-ID
//	azurekv://VAULT.vault.azure.net/keys/NAME/VERSION
//
// The scheme names the backend; each backend package (e.g.
// cmd/janos/diviner/gcpkms) calls Register in its init() to make
// itself available.
//
// There is deliberately no `file://` scheme.  Production JanOS binaries
// must never be signed with a locally-held key — the whole point of
// the diviner subsystem is to force signing through an HSM boundary.
package diviner

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Diviner produces ECDSA P-256 signatures over pre-hashed 32-byte
// SHA-256 digests.  Implementations are backed by an HSM-protected
// KMS in production; test code uses an in-package mock that wraps
// stdlib crypto/ecdsa driven from a deterministic seed.
//
// P-256 was chosen over Ed25519 because Google Cloud KMS does not
// offer HSM-level protection for Ed25519 keys — the whole point of
// the diviner subsystem is HSM-boundary signing, so an
// HSM-supported curve is required.  Signatures are returned in the
// wire format the runtime verifier expects: 64 bytes r || s, each
// 32 bytes big-endian.  Backends that speak DER (Cloud KMS does)
// unwrap the ASN.1 before returning.
type Diviner interface {
	// PublicKey returns the ECDSA P-256 public key of the KMS-held
	// signing key this diviner is authorized to invoke.  64 bytes,
	// uncompressed X || Y (no SEC1 0x04 prefix).  Consumers cross-
	// check this against the value stored in the signet file to
	// confirm the URL and the signet agree on which key is
	// authoritative.
	PublicKey() ([64]byte, error)

	// Sign produces a 64-byte ECDSA P-256 signature (r || s) over
	// digest.  Errors surface KMS-level failures (auth, network,
	// quota, revocation).  Callers translate an error to a hard
	// link failure — a JanOS binary that cannot be divined must not
	// be produced.
	Sign(digest [32]byte) ([64]byte, error)
}

// Factory constructs a Diviner from a scheme-qualified URL.  Each
// backend registers one factory per scheme.
type Factory func(url string) (Diviner, error)

var (
	registryMu sync.RWMutex
	registry   = map[string]Factory{}
)

// Register makes factory available under the given URL scheme.  Backend
// packages call this from init().  Duplicate registrations replace the
// prior entry — the last package init'd wins.  Not currently a concern
// (one backend per scheme), but keep the semantics predictable.
func Register(scheme string, factory Factory) {
	if scheme == "" {
		panic("diviner: Register: empty scheme")
	}
	if factory == nil {
		panic("diviner: Register: nil factory")
	}
	if strings.Contains(scheme, "://") {
		panic("diviner: Register: scheme must not contain '://'")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[scheme] = factory
}

// Open returns a Diviner for the given URL by dispatching on the URL's
// scheme.  Callers pass the URL exactly as it appears in the signet
// file's guild_diviner or release_diviner field.
//
// Errors:
//   - `diviner: URL missing scheme` — no `://` in the URL
//   - `diviner: file:// scheme is forbidden` — explicit ban on
//     locally-held keys; any tooling that surfaces this error should
//     tell the user their signet needs a KMS URL instead
//   - `diviner: no backend registered for scheme %q` — backend not
//     imported (typically because a build target dropped it via
//     linker flags, or the URL uses a scheme not yet supported)
//   - anything the backend's factory returns from URL parsing or
//     initial KMS connectivity checks
func Open(url string) (Diviner, error) {
	i := strings.Index(url, "://")
	if i < 0 {
		return nil, errors.New("diviner: URL missing scheme")
	}
	scheme := url[:i]
	if scheme == "file" {
		return nil, errors.New("diviner: file:// scheme is forbidden — JanOS requires HSM-backed KMS signing at all times")
	}

	registryMu.RLock()
	factory := registry[scheme]
	registryMu.RUnlock()

	if factory == nil {
		return nil, fmt.Errorf("diviner: no backend registered for scheme %q", scheme)
	}
	return factory(url)
}

// RegisteredSchemes returns the schemes for which a backend has been
// registered.  Useful for building "which schemes does this build
// support?" diagnostics.
func RegisteredSchemes() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(registry))
	for scheme := range registry {
		out = append(out, scheme)
	}
	return out
}
