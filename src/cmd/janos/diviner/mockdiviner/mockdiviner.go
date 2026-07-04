// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build janos_signtest

// Package mockdiviner registers a test-only diviner backend under
// the mockdiviner:// scheme.  Only compiled with -tags janos_signtest.
//
// Purpose: give tests (and any downstream tests that need real
// Ed25519 signatures during unit testing) a signer they can drive
// deterministically.  The mock wraps internal/runtime/janos_ed25519's
// test-only SignForTest.
//
// This package lives outside cmd/janos/diviner because cmd/janos/diviner
// is bootstrap-copied, and bootstrap forbids imports of internal/*.
// Living here keeps the mock's dependency on
// internal/runtime/janos_ed25519 out of the bootstrap scan.
//
// Tests that want mockdiviner scheme available do:
//
//	import _ "cmd/janos/diviner/mockdiviner"
package mockdiviner

import (
	"encoding/hex"
	"fmt"
	"internal/runtime/janos_ed25519"
	"strings"

	"cmd/janos/diviner"
)

// mockDiviner signs and verifies against a deterministic seed derived
// from the URL path.  URL format: `mockdiviner://SEEDHEX` where
// SEEDHEX is up to 64 hex characters (right-padded with zeros so
// short labels like "guild" or "release" give distinct seeds).
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

func open(url string) (diviner.Diviner, error) {
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
	diviner.Register("mockdiviner", open)
}
