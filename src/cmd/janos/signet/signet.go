// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package signet parses the JanOS repo's `signet` file, which
// declares the KMS-backed signing keys the toolchain uses during a
// build.  cmd/link reads it at link time to know:
//
//   - which Guild root public key to bake into the runtime
//   - which Release public key to expect on this binary's signatures
//   - which KMS URL to invoke for the release-level sig on every build
//
// No private key material appears in the signet file.  All references
// are KMS URLs (gcpkms://, awskms://, azurekv://, etc.).  Failure to
// authenticate with the named KMS at build time is a hard link
// error; there is no --skip-signing flag.
package signet

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Config is the parsed contents of a signet file.
type Config struct {
	// GuildPubKey is the 32-byte Ed25519 public key of the
	// Enigmaneering Guild's non-revocable root, used by the runtime
	// to verify every Guild-level signature.  Hex-encoded in the
	// file; decoded on load.
	GuildPubKey [32]byte

	// GuildDiviner is the KMS URL of the Guild's root signing key.
	// Only invoked during release-ceremony builds; regular builds
	// don't call it.  Empty string means "not a release ceremony
	// build" — cmd/link will refuse to build if this is required
	// (e.g., when producing a new release_pubkey signature) but
	// otherwise ignores it.
	GuildDiviner string

	// ReleasePubKey is the 32-byte Ed25519 public key of this
	// release's signing keypair.
	ReleasePubKey [32]byte

	// ReleaseDiviner is the KMS URL for this release's signing key.
	// cmd/link invokes it on every build.  Must be a non-file://
	// scheme in production; presence of file:// causes a link error.
	ReleaseDiviner string

	// ReleaseParentCert is Guild's Ed25519 signature over
	// ReleasePubKey — the chain-of-trust link that lets Release
	// certificates validate against the Guild root.  Produced once
	// during a release ceremony.  Embedded into the JANOSCRT slot's
	// Release entry as parent_cert.
	ReleaseParentCert [64]byte

	// ReleaseEpoch is the monotonic serial for this release's
	// signing key.  Appears in the JANOSCRT slot as revoke_epoch.
	ReleaseEpoch uint32
}

// Load reads and parses the signet file at path.  Returns a
// populated Config or an error explaining the first problem
// encountered.  A missing file, wrong-length hex value, or
// unrecognized scheme in a diviner URL is a fatal error.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("signet: open %s: %w", path, err)
	}
	defer f.Close()
	return Parse(f)
}

// Parse decodes a signet file from r.  Exported so cmd/link tests
// can feed in synthetic contents without touching the filesystem.
func Parse(r io.Reader) (*Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("signet: read: %w", err)
	}
	c := &Config{}
	var releaseParentCertHex string
	for lineno, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("signet: line %d: missing '='", lineno+1)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		switch key {
		case "guild_pubkey":
			if err := decodeHex32(val, &c.GuildPubKey); err != nil {
				return nil, fmt.Errorf("signet: line %d guild_pubkey: %w", lineno+1, err)
			}
		case "guild_diviner":
			c.GuildDiviner = val
		case "release_pubkey":
			if err := decodeHex32(val, &c.ReleasePubKey); err != nil {
				return nil, fmt.Errorf("signet: line %d release_pubkey: %w", lineno+1, err)
			}
		case "release_diviner":
			c.ReleaseDiviner = val
		case "release_parent_cert":
			releaseParentCertHex = val
		case "release_epoch":
			if val == "" {
				continue
			}
			n, err := strconv.ParseUint(val, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("signet: line %d release_epoch: %w", lineno+1, err)
			}
			c.ReleaseEpoch = uint32(n)
		default:
			return nil, fmt.Errorf("signet: line %d: unknown key %q", lineno+1, key)
		}
	}

	if releaseParentCertHex != "" {
		decoded, err := hex.DecodeString(releaseParentCertHex)
		if err != nil {
			return nil, fmt.Errorf("signet: release_parent_cert: %w", err)
		}
		if len(decoded) != 64 {
			return nil, fmt.Errorf("signet: release_parent_cert: want 64 bytes, got %d", len(decoded))
		}
		copy(c.ReleaseParentCert[:], decoded)
	}

	return c, nil
}

// ValidateForBuild checks that a Config has everything a regular
// (non-release-ceremony) build needs.  Returns an error naming the
// first missing or malformed piece; nil on success.
func (c *Config) ValidateForBuild() error {
	if c.GuildPubKey == ([32]byte{}) {
		return errors.New("signet: guild_pubkey is empty; cannot bake a Guild root into the runtime")
	}
	if c.ReleasePubKey == ([32]byte{}) {
		return errors.New("signet: release_pubkey is empty; cannot bake a Release identity into the runtime")
	}
	if c.ReleaseDiviner == "" {
		return errors.New("signet: release_diviner KMS URL is empty; cannot sign this build")
	}
	if err := validateDivinerScheme(c.ReleaseDiviner); err != nil {
		return fmt.Errorf("signet: release_diviner: %w", err)
	}
	if c.ReleaseParentCert == ([64]byte{}) {
		return errors.New("signet: release_parent_cert is empty; the Guild has not authorized this release")
	}
	return nil
}

// validateDivinerScheme rejects file:// (never allowed) and unknown
// schemes.  Recognized production schemes: gcpkms://, awskms://,
// azurekv://.  New schemes are added here as the toolchain grows
// diviner implementations.
func validateDivinerScheme(url string) error {
	i := strings.Index(url, "://")
	if i < 0 {
		return fmt.Errorf("missing scheme (expected e.g. gcpkms://...)")
	}
	scheme := url[:i]
	switch scheme {
	case "gcpkms", "awskms", "azurekv":
		return nil
	case "file":
		return errors.New("file:// diviner scheme is forbidden — JanOS requires HSM-backed KMS signing at all times")
	default:
		return fmt.Errorf("unknown diviner scheme %q; supported: gcpkms, awskms, azurekv", scheme)
	}
}

func decodeHex32(s string, out *[32]byte) error {
	if s == "" {
		return nil
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(decoded) != 32 {
		return fmt.Errorf("want 32 bytes, got %d", len(decoded))
	}
	copy(out[:], decoded)
	return nil
}
