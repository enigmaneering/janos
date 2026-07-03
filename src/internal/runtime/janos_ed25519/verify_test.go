// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package janos_ed25519

import (
	"testing"
)

// hexDecode is a tiny hex decoder for test vectors; keeping this
// self-contained avoids pulling encoding/hex into internal/runtime.
func hexDecode(t *testing.T, s string) []byte {
	t.Helper()
	if len(s)%2 != 0 {
		t.Fatalf("odd-length hex: %q", s)
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var hi, lo byte
		for _, pair := range [2]struct {
			c   byte
			out *byte
		}{{s[2*i], &hi}, {s[2*i+1], &lo}} {
			switch {
			case pair.c >= '0' && pair.c <= '9':
				*pair.out = pair.c - '0'
			case pair.c >= 'a' && pair.c <= 'f':
				*pair.out = pair.c - 'a' + 10
			case pair.c >= 'A' && pair.c <= 'F':
				*pair.out = pair.c - 'A' + 10
			default:
				t.Fatalf("bad hex char %q in %q", pair.c, s)
			}
		}
		out[i] = hi<<4 | lo
	}
	return out
}

// TestVerifyRFC8032 runs the three abbreviated test vectors from RFC 8032
// §7.1 (Ed25519).  These vectors ARE the golden reference; if any of
// them fails, the port is broken.
func TestVerifyRFC8032(t *testing.T) {
	cases := []struct {
		name string
		pub  string
		msg  string
		sig  string
	}{
		{
			name: "TEST 1",
			pub:  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
			msg:  "",
			sig: "e5564300c360ac729086e2cc806e828a" +
				"84877f1eb8e5d974d873e06522490155" +
				"5fb8821590a33bacc61e39701cf9b46b" +
				"d25bf5f0595bbe24655141438e7a100b",
		},
		{
			name: "TEST 2",
			pub:  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
			msg:  "72",
			sig: "92a009a9f0d4cab8720e820b5f642540" +
				"a2b27b5416503f8fb3762223ebdb69da" +
				"085ac1e43e15996e458f3613d0f11d8c" +
				"387b2eaeb4302aeeb00d291612bb0c00",
		},
		{
			name: "TEST 3",
			pub:  "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
			msg:  "af82",
			sig: "6291d657deec24024827e69c3abe01a3" +
				"0ce548a284743a445e3680d7db5ac3ac" +
				"18ff9b538d16f290ae67f760984dc659" +
				"4a7c15e9716ed28dc027beceea1ec40a",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pub := hexDecode(t, c.pub)
			msg := hexDecode(t, c.msg)
			sig := hexDecode(t, c.sig)
			if !Verify(pub, msg, sig) {
				t.Fatal("valid RFC 8032 vector rejected")
			}
		})
	}
}

// TestVerifyTamperedSig ensures a flipped bit in the signature causes
// verification to fail.
func TestVerifyTamperedSig(t *testing.T) {
	pub := hexDecode(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	sig := hexDecode(t,
		"e5564300c360ac729086e2cc806e828a"+
			"84877f1eb8e5d974d873e06522490155"+
			"5fb8821590a33bacc61e39701cf9b46b"+
			"d25bf5f0595bbe24655141438e7a100b")
	sig[0] ^= 1
	if Verify(pub, nil, sig) {
		t.Fatal("Verify accepted tampered signature")
	}
}

// TestVerifyTamperedMsg ensures a mutated message causes rejection.
func TestVerifyTamperedMsg(t *testing.T) {
	pub := hexDecode(t, "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
	sig := hexDecode(t,
		"92a009a9f0d4cab8720e820b5f642540"+
			"a2b27b5416503f8fb3762223ebdb69da"+
			"085ac1e43e15996e458f3613d0f11d8c"+
			"387b2eaeb4302aeeb00d291612bb0c00")
	if Verify(pub, []byte{0x73}, sig) { // real msg is 0x72
		t.Fatal("Verify accepted signature over wrong message")
	}
}

// TestVerifyWrongPubKey ensures a different public key rejects the
// signature.
func TestVerifyWrongPubKey(t *testing.T) {
	pub := hexDecode(t, "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
	sig := hexDecode(t,
		"6291d657deec24024827e69c3abe01a3"+
			"0ce548a284743a445e3680d7db5ac3ac"+
			"18ff9b538d16f290ae67f760984dc659"+
			"4a7c15e9716ed28dc027beceea1ec40a")
	msg := hexDecode(t, "af82")

	otherPub := hexDecode(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if Verify(otherPub, msg, sig) {
		t.Fatal("Verify accepted a sig from a different key")
	}
	// Sanity: same sig verifies with the correct key.
	if !Verify(pub, msg, sig) {
		t.Fatal("Verify rejected valid vector")
	}
}

// TestVerifyMalformedLengths covers wrong-size arguments.
func TestVerifyMalformedLengths(t *testing.T) {
	pub := hexDecode(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	sig := hexDecode(t,
		"e5564300c360ac729086e2cc806e828a"+
			"84877f1eb8e5d974d873e06522490155"+
			"5fb8821590a33bacc61e39701cf9b46b"+
			"d25bf5f0595bbe24655141438e7a100b")
	if Verify(pub[:31], nil, sig) {
		t.Error("short pub accepted")
	}
	if Verify(pub, nil, sig[:63]) {
		t.Error("short sig accepted")
	}
	// High bits set in sig[63] -> reject.
	bad := make([]byte, 64)
	copy(bad, sig)
	bad[63] |= 0b11100000
	if Verify(pub, nil, bad) {
		t.Error("sig with high bits in s accepted")
	}
}
