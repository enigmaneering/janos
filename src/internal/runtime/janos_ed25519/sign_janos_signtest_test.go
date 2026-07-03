// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build janos_signtest

package janos_ed25519

import "testing"

// TestSignVerifyRoundTrip proves SignForTest + Verify agree on the
// RFC 8032 procedure — a stronger check than static test vectors
// alone.
func TestSignVerifyRoundTrip(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i) * 3
	}
	messages := [][]byte{
		nil,
		[]byte("hello"),
		[]byte("The quick brown fox jumps over the lazy dog"),
	}
	for i, m := range messages {
		pub, sig := SignForTest(seed, m)
		if !Verify(pub[:], m, sig[:]) {
			t.Errorf("case %d: fresh signature did not verify", i)
		}
		if len(m) > 0 {
			bad := make([]byte, len(m))
			copy(bad, m)
			bad[0] ^= 1
			if Verify(pub[:], bad, sig[:]) {
				t.Errorf("case %d: verify accepted tampered message", i)
			}
		}
	}
}
