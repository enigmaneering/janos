// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build janos_signtest

// A "mock" diviner backend, ONLY compiled with -tags janos_signtest.
// Production JanOS builds never see this file: the scheme
// `mockdiviner://` is not registered, so cmd/link's diviner pass would
// reject a URL naming it.
//
// Purpose: give the diviner package's own tests (and any downstream
// tests that need real Ed25519 signatures during unit testing) a
// signer they can drive deterministically.  The mock wraps
// internal/runtime/janos_ed25519's test-only SignForTest.

package diviner

import (
	"encoding/hex"
	"fmt"
	"internal/runtime/janos_ed25519"
	"strings"
)

// mockDiviner signs and verifies against a deterministic seed derived
// from the URL path.  URL format: `mockdiviner://SEEDHEX` where
// SEEDHEX is up to 64 hex characters (padded with zeros to 32 bytes
// on the low-order side).
type mockDiviner struct {
	seed [32]byte
}

func (m *mockDiviner) PublicKey() ([32]byte, error) {
	pk, _ := janos_ed25519.SignForTest(m.seed, nil)
	return pk, nil
}

func (m *mockDiviner) Sign(digest [32]byte) ([64]byte, error) {
	_, sig := janos_ed25519.SignForTest(m.seed, digest[:])
	return sig, nil
}

func mockOpen(url string) (Diviner, error) {
	const prefix = "mockdiviner://"
	if !strings.HasPrefix(url, prefix) {
		return nil, fmt.Errorf("mockdiviner: URL %q does not start with %q", url, prefix)
	}
	seedHex := url[len(prefix):]
	if len(seedHex) == 0 {
		return nil, fmt.Errorf("mockdiviner: URL %q is missing seed hex", url)
	}
	if len(seedHex) > 64 {
		return nil, fmt.Errorf("mockdiviner: seed hex too long (%d chars, max 64)", len(seedHex))
	}
	// Pad seedHex on the right so a caller can pass a short label
	// like "guild" and get a stable, distinct 32-byte seed.
	for len(seedHex) < 64 {
		seedHex += "0"
	}
	decoded, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, fmt.Errorf("mockdiviner: bad seed hex %q: %w", seedHex, err)
	}
	m := &mockDiviner{}
	copy(m.seed[:], decoded)
	return m, nil
}

func init() {
	Register("mockdiviner", mockOpen)
}
