// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"runtime"
	"testing"
)

// ecdsaTestPubKey: the P-256 public key used to sign the test
// vectors below.  Generated in the scratchpad from a deterministic
// SHA-256 seed so the fixture is reproducible.
var ecdsaTestPubKey = [64]byte{
	0x1b, 0xc0, 0xd4, 0xe2, 0x25, 0x00, 0xf0, 0x28,
	0xec, 0xd5, 0xa2, 0x7a, 0xe6, 0x92, 0x18, 0xb5,
	0x78, 0x82, 0x27, 0xe6, 0x53, 0xaa, 0xb2, 0xc0,
	0xa7, 0x6e, 0x54, 0xe5, 0x43, 0xb1, 0x2c, 0x0b,
	0xd5, 0x04, 0xc2, 0xe1, 0x7d, 0xaf, 0x04, 0x44,
	0x8d, 0x0c, 0x04, 0x5f, 0x1a, 0x77, 0xda, 0x78,
	0x1c, 0x19, 0x4c, 0xfb, 0xe8, 0x63, 0x2d, 0x86,
	0x79, 0x7e, 0xf3, 0x8e, 0xec, 0x5b, 0x1d, 0x26,
}

// ecdsaTestVectors: (message, r||s hex).  Each signature was
// produced by stock crypto/ecdsa with SHA-256 digests.
var ecdsaTestVectors = [...]struct{ msg, sig string }{
	{"hello",
		"3fb82d18397cc4fc0c21339712644a4229bfcc23098b84e8cd84c555344ac61a" +
			"8f2f5874ef4ba3f1184c6b90ca07bc7b024bc324177b5331f6a620f77f26a530"},
	{"The quick brown fox jumps over the lazy dog",
		"bab576eacce256c0fc4782715e8de1a3b1fb028b1caaeb43620039edad961093" +
			"2c50a44509dfad189a8d820ccfb8fbd8a5f8b28c443ef9d475d2ff684f546056"},
	{"",
		"c1bc35e0d875a0cf2368422acd8439fe6bf55222011dded35afdf56d4346416e" +
			"a8befa92d1a6ad23147b7683ce1e385977eefb9d3f18b44e435421492633b27e"},
	{"a",
		"f7df9fa90c73688b073bfe97d92f172889b104caee208356b86a110ccccb67a6" +
			"a1189c1b135498d475d082c00545b1689f31f0830e59f6e4ac376439acf3349a"},
	{"janos-colonel-genesis",
		"eb8731d583b26ed4624c774f3c36e4058d58f90094b98830d86c9f51fe754d33" +
			"477687484164fecfed3693ac023edb6f9feb07f7b0232ed88c83acfdcf112492"},
}

// TestJanosP256ECDSAAccept: verify accepts each valid (msg, sig)
// pair from the test vectors.
func TestJanosP256ECDSAAccept(t *testing.T) {
	for i, v := range ecdsaTestVectors {
		digest := runtime.JanosSHA256ForTest([]byte(v.msg))
		sig := unhex(t, v.sig)
		if !runtime.P256VerifyForTest(ecdsaTestPubKey[:], digest[:], sig) {
			t.Errorf("case %d (msg=%q): valid signature rejected", i, v.msg)
		}
	}
}

// TestJanosP256ECDSARejectWrongDigest: flipping one bit of the
// digest must produce a rejected signature.
func TestJanosP256ECDSARejectWrongDigest(t *testing.T) {
	v := ecdsaTestVectors[0]
	digest := runtime.JanosSHA256ForTest([]byte(v.msg))
	digest[0] ^= 0x01 // flip the low bit of the first byte
	sig := unhex(t, v.sig)
	if runtime.P256VerifyForTest(ecdsaTestPubKey[:], digest[:], sig) {
		t.Error("verify accepted a signature against a modified digest")
	}
}

// TestJanosP256ECDSARejectWrongSig: flipping one bit of r (or s)
// must reject.  We test both.
func TestJanosP256ECDSARejectWrongSig(t *testing.T) {
	v := ecdsaTestVectors[0]
	digest := runtime.JanosSHA256ForTest([]byte(v.msg))

	// Flip a bit inside r.
	sig := unhex(t, v.sig)
	sig[0] ^= 0x01
	if runtime.P256VerifyForTest(ecdsaTestPubKey[:], digest[:], sig) {
		t.Error("verify accepted a signature with r[0]^=1")
	}
	// Flip a bit inside s.
	sig = unhex(t, v.sig)
	sig[63] ^= 0x01
	if runtime.P256VerifyForTest(ecdsaTestPubKey[:], digest[:], sig) {
		t.Error("verify accepted a signature with s[31]^=1")
	}
}

// TestJanosP256ECDSARejectWrongPubKey: verify against a different
// public key must reject.  We flip a bit of X, which almost
// certainly puts it off the curve — SetUncompressedBytes should
// refuse and verify should return false.
func TestJanosP256ECDSARejectWrongPubKey(t *testing.T) {
	v := ecdsaTestVectors[0]
	digest := runtime.JanosSHA256ForTest([]byte(v.msg))
	sig := unhex(t, v.sig)

	badPK := ecdsaTestPubKey
	badPK[0] ^= 0x01
	if runtime.P256VerifyForTest(badPK[:], digest[:], sig) {
		t.Error("verify accepted a signature under an off-curve public key")
	}
}

// TestJanosP256ECDSARejectZeroRS: r=0 or s=0 must be rejected per
// FIPS 186-4 §6.4.2 step 1.
func TestJanosP256ECDSARejectZeroRS(t *testing.T) {
	v := ecdsaTestVectors[0]
	digest := runtime.JanosSHA256ForTest([]byte(v.msg))

	// Zero r.
	sig := unhex(t, v.sig)
	for i := 0; i < 32; i++ {
		sig[i] = 0
	}
	if runtime.P256VerifyForTest(ecdsaTestPubKey[:], digest[:], sig) {
		t.Error("verify accepted r = 0")
	}

	// Zero s.
	sig = unhex(t, v.sig)
	for i := 32; i < 64; i++ {
		sig[i] = 0
	}
	if runtime.P256VerifyForTest(ecdsaTestPubKey[:], digest[:], sig) {
		t.Error("verify accepted s = 0")
	}
}

// TestJanosP256ECDSARejectROrSAtOrAboveN: r or s equal to the curve
// order n (or larger) must be rejected.  This checks the strict
// bytes-less-than-n gate — without it, SetBytesBE would silently
// reduce n to 0 and be caught by the zero check, but n+1 would go
// through as 1 and could produce a "successful" forgery.
func TestJanosP256ECDSARejectROrSAtOrAboveN(t *testing.T) {
	v := ecdsaTestVectors[0]
	digest := runtime.JanosSHA256ForTest([]byte(v.msg))

	// n = ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
	nBytes := unhex(t, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")

	// r = n
	sig := unhex(t, v.sig)
	copy(sig[:32], nBytes)
	if runtime.P256VerifyForTest(ecdsaTestPubKey[:], digest[:], sig) {
		t.Error("verify accepted r = n")
	}

	// s = n
	sig = unhex(t, v.sig)
	copy(sig[32:], nBytes)
	if runtime.P256VerifyForTest(ecdsaTestPubKey[:], digest[:], sig) {
		t.Error("verify accepted s = n")
	}

	// r = n + 1 (would silently reduce to 1 without a strict check)
	sig = unhex(t, v.sig)
	copy(sig[:32], nBytes)
	sig[31] += 1
	if runtime.P256VerifyForTest(ecdsaTestPubKey[:], digest[:], sig) {
		t.Error("verify accepted r = n + 1 (should be rejected as >= n)")
	}
}

// unhex is a tiny hex decoder for tests — encoding/hex sits above
// runtime.  Length must be even.
func unhex(t *testing.T, s string) []byte {
	t.Helper()
	if len(s)%2 != 0 {
		t.Fatalf("unhex: odd length %d", len(s))
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		out[i] = hexNibble(t, s[2*i])<<4 | hexNibble(t, s[2*i+1])
	}
	return out
}
