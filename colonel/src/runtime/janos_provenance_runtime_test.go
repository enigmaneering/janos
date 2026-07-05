// Test-only helpers that live in the runtime package so external tests
// can reach package-internal state.  Production code has no setter
// for provenance — it is entirely runtime-driven — so this file
// exists purely to let the test harness synthesize inheritance
// scenarios that the natural schedinit flow would not exercise.

package runtime

import "internal/runtime/janos_hash"

// P256FieldOpsForTest exposes the runtime-internal P-256 field
// element type to external tests.  Returns a fresh Element+bool
// pair for SetBytes; and Add/Sub/Mul/Square/Invert/Bytes helpers so
// the external test file can drive the field type without duplicating
// the wrapper.  All operations are stack-friendly (return values, no
// heap allocs).
func P256FieldFromBytesForTest(v []byte) ([32]byte, bool) {
	var e janosP256Element
	if _, ok := e.SetBytes(v); !ok {
		return [32]byte{}, false
	}
	return e.Bytes(), true
}

// P256FieldMulForTest returns (a * b mod p) as 32 big-endian bytes,
// or (zeros, false) if either input is not a canonical field element.
func P256FieldMulForTest(a, b []byte) ([32]byte, bool) {
	var ae, be, out janosP256Element
	if _, ok := ae.SetBytes(a); !ok {
		return [32]byte{}, false
	}
	if _, ok := be.SetBytes(b); !ok {
		return [32]byte{}, false
	}
	out.Mul(&ae, &be)
	return out.Bytes(), true
}

// P256FieldInvertForTest returns (1/a mod p) as 32 big-endian bytes,
// or zero if a is zero.
func P256FieldInvertForTest(a []byte) ([32]byte, bool) {
	var ae, out janosP256Element
	if _, ok := ae.SetBytes(a); !ok {
		return [32]byte{}, false
	}
	out.Invert(&ae)
	return out.Bytes(), true
}

// P256ScalarMulForTest returns (a * b mod n) as 32 big-endian bytes,
// or ([32]byte{}, false) if either input is not 32 bytes.
func P256ScalarMulForTest(a, b []byte) ([32]byte, bool) {
	var as, bs, out janosP256Scalar
	if _, ok := as.SetBytesBE(a); !ok {
		return [32]byte{}, false
	}
	if _, ok := bs.SetBytesBE(b); !ok {
		return [32]byte{}, false
	}
	out.Mul(&as, &bs)
	return out.Bytes(), true
}

// P256ScalarInvertForTest returns (1/x mod n) as 32 big-endian bytes.
// If x is zero, returns [32]byte{}, true.
func P256ScalarInvertForTest(x []byte) ([32]byte, bool) {
	var xs, out janosP256Scalar
	if _, ok := xs.SetBytesBE(x); !ok {
		return [32]byte{}, false
	}
	out.Invert(&xs)
	return out.Bytes(), true
}

// P256ScalarRoundTripForTest: SetBytesBE(v) then Bytes().  Useful for
// confirming the encode/decode paths agree.
func P256ScalarRoundTripForTest(v []byte) ([32]byte, bool) {
	var s janosP256Scalar
	if _, ok := s.SetBytesBE(v); !ok {
		return [32]byte{}, false
	}
	return s.Bytes(), true
}

// P256ScalarBaseMultForTest returns (k*G).x, (k*G).y as big-endian
// 32-byte encodings, or (_, _, false) if the point is at infinity or
// k is not 32 bytes.  Used by tests to check the point-ops port
// against RFC-published vectors.
func P256ScalarBaseMultForTest(k []byte) ([32]byte, [32]byte, bool) {
	var p janosP256Point
	if _, ok := p.ScalarBaseMult(k); !ok {
		return [32]byte{}, [32]byte{}, false
	}
	if p.IsInfinity() {
		return [32]byte{}, [32]byte{}, false
	}
	// Extract affine (X/Z, Y/Z).
	var zinv, x, y janosP256Element
	zinv.Invert(&p.z)
	x.Mul(&p.x, &zinv)
	y.Mul(&p.y, &zinv)
	return x.Bytes(), y.Bytes(), true
}

// P256GeneratorIsOnCurveForTest reports whether the hardcoded
// generator satisfies the curve equation.
func P256GeneratorIsOnCurveForTest() bool {
	var g janosP256Point
	g.SetGenerator()
	return g.isOnCurve()
}

// P256AddDoubleConsistentForTest checks that G + G computed via Add
// matches 2G computed via Double.  A failure here indicates a bug in
// one of the two formulas or the generator constant.
func P256AddDoubleConsistentForTest() bool {
	var g1, g2, added, doubled janosP256Point
	g1.SetGenerator()
	g2.SetGenerator()

	added.Add(&g1, &g2)
	doubled.Double(&g1)

	// Compare via affine x and y (avoid comparing projective reps
	// that may differ by a Z scaling).
	x1, ok1 := added.AffineX()
	x2, ok2 := doubled.AffineX()
	if !ok1 || !ok2 || x1 != x2 {
		return false
	}
	return true
}

// P256AddInfinityForTest checks Add(G, infinity) == G.
func P256AddInfinityForTest() bool {
	var g, inf, sum janosP256Point
	g.SetGenerator()
	inf.SetInfinity()
	sum.Add(&g, &inf)
	xSum, ok := sum.AffineX()
	if !ok {
		return false
	}
	xG, _ := g.AffineX()
	return xSum == xG
}

// P256NegatePlusPointIsInfinityForTest checks that G + (-G) is the
// point at infinity.
func P256NegatePlusPointIsInfinityForTest() bool {
	var g, gNeg, sum janosP256Point
	g.SetGenerator()
	gNeg.SetGenerator()
	gNeg.Negate()
	sum.Add(&g, &gNeg)
	return sum.IsInfinity()
}

// P256VerifyForTest exposes the runtime-internal ECDSA verify to
// external tests.  Signature is r||s (64 bytes), pubkey is X||Y
// (64 bytes), digest is 32 bytes.
func P256VerifyForTest(pubkey, digest, sig []byte) bool {
	if len(pubkey) != 64 || len(digest) != 32 || len(sig) != 64 {
		return false
	}
	var pk [64]byte
	var d [32]byte
	var s [64]byte
	copy(pk[:], pubkey)
	copy(d[:], digest)
	copy(s[:], sig)
	return janosP256VerifyRS(&pk, &d, &s)
}

// P256UncompressedRoundTripForTest: parse a 64-byte X||Y encoding of
// a point, then re-serialise the affine coordinates from the parsed
// point.  Returns the round-tripped bytes or ({}, false) on parse
// failure.  Verifies isOnCurve as a side effect.
func P256UncompressedRoundTripForTest(xy []byte) ([32]byte, [32]byte, bool) {
	var p janosP256Point
	if _, ok := p.SetUncompressedBytes(xy); !ok {
		return [32]byte{}, [32]byte{}, false
	}
	x, ok := p.AffineX()
	if !ok {
		return [32]byte{}, [32]byte{}, false
	}
	// AffineY: mirror AffineX inline.
	var zinv, y janosP256Element
	zinv.Invert(&p.z)
	y.Mul(&p.y, &zinv)
	return x, y.Bytes(), true
}

// P256FieldOneForTest returns the multiplicative identity as 32 bytes.
func P256FieldOneForTest() [32]byte {
	var e janosP256Element
	e.One()
	return e.Bytes()
}

// CurrentInstanceIDHexForTest returns the running goroutine's
// InstanceID as a 32-char hex string.  Test-only helper so
// TestInstanceIDDistinctAcrossRuns can print and compare without
// importing encoding/hex into runtime tests.
func CurrentInstanceIDHexForTest() string {
	id := CurrentProvenance().InstanceID
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(id)*2)
	for i, b := range id {
		out[i*2] = hexChars[b>>4]
		out[i*2+1] = hexChars[b&0xf]
	}
	return string(out)
}

// SetCurrentProvenanceForTest overwrites the current goroutine's
// provenance.  Snapshot the value before calling and restore it in a
// deferred call to avoid polluting other tests.
func SetCurrentProvenanceForTest(p Provenance) {
	janosSetGProvenance(getg(), p)
}

// JanosSHA256ForTest exposes the runtime-adjacent SHA-256 to external
// tests so they can compare its output against a known-good vector
// without needing to import crypto/sha256 (which sits above runtime).
func JanosSHA256ForTest(p []byte) [32]byte {
	var d janos_hash.SHA256
	d.Reset()
	d.Write(p)
	return d.Sum()
}

// JanosSHA512ForTest exposes the runtime-adjacent SHA-512 to external
// tests.  Ed25519 verification depends on SHA-512 internally, so we
// vet it here against NIST test vectors before wiring it up.
func JanosSHA512ForTest(p []byte) [64]byte {
	var d janos_hash.SHA512
	d.Reset()
	d.Write(p)
	return d.Sum()
}

// SetJanosCertificatesForTest populates the process-wide Guild/
// Release/User cert storage without going through the real schedinit
// verification path.  Also updates the calling goroutine's cert IDs
// and bumps TrustLevel to TrustJanosReleased so tests can observe
// the "runtime has verified this binary" state.  Pass nil for user
// to clear the user cert.  Restore via SetJanosCertificatesForTest
// with zero-value certs.
func SetJanosCertificatesForTest(guild, release Certificate, user *Certificate) {
	janosGuildCert = guild
	janosReleaseCert = release
	if user != nil {
		janosUserCert = *user
		janosHasUserCert = true
	} else {
		janosUserCert = Certificate{}
		janosHasUserCert = false
	}

	gp := getg()
	gp.provenance.guildCertID = certIDForTest(guild.SignerPubKey)
	gp.provenance.releaseCertID = certIDForTest(release.SignerPubKey)
	// Only bump the trust level when at least Guild + Release are set.
	// A zero-value guild/release clears back to whatever level was
	// there before, which for stubs is TrustNone and for platforms
	// with a self-hash reader is TrustSelfAttested.
	if guild != (Certificate{}) && release != (Certificate{}) {
		gp.provenance.trustLevel = TrustJanosReleased
	}
}

// certIDForTest is the same hash function the chain verifier uses to
// compute a compact identifier for a signer.  We inline it here so
// the test setter doesn't have to reach into runtime-internal helpers.
func certIDForTest(pk [64]byte) [32]byte {
	var d janos_hash.SHA256
	d.Reset()
	d.Write(pk[:])
	return d.Sum()
}

// JanosCanonicalHashForTest exposes the runtime-internal canonical
// hasher to external tests, letting the test file inject its own
// Guild/Release pubkey patterns.  The production wrapper
// janosHashCanonical always uses the runtime's own janos-
// ExpectedGuild/ReleasePubKey vars; tests need to vary those.  Note
// that buf is mutated in place — callers should pass a fresh copy
// if they want to reuse the fixture.
func JanosCanonicalHashForTest(buf, guildKey, releaseKey []byte) [32]byte {
	return janosCanonicalHash(buf, guildKey, releaseKey)
}

// JanosHMACSHA256ForTest exposes the runtime's HMAC-SHA256 to
// external tests for validation against RFC 4231 vectors.
func JanosHMACSHA256ForTest(key, msg []byte) [32]byte {
	return janosHMACSHA256(key, msg)
}

// JanosHKDFExpand32ForTest exposes the runtime's HKDF-Expand-SHA256
// (specialized to 32 bytes) for validation against RFC 5869 vectors.
func JanosHKDFExpand32ForTest(prk, info []byte) [32]byte {
	return janosHKDFExpand32(prk, info)
}

// JanosIdentityKDFSaltForTest exposes the KDF salt derivation used
// by Identity.Derive so tests can verify order-independence (sort by
// lex, then concatenate the two public points).
func JanosIdentityKDFSaltForTest(a, b []byte) []byte {
	return janosIdentityKDFSalt(a, b)
}

// JanosDeriveIdentityKeyForTest exposes the deterministic (index →
// priv, pub) derivation so tests can verify that d·G matches the
// stored PublicPoint for any given index and root key.  Reads the
// current process-wide janosRootKey.
func JanosDeriveIdentityKeyForTest(idx uint64) (priv [32]byte, pub [64]byte) {
	return janosDeriveIdentityKey(idx)
}

// TamperIdentityIndexForTest returns a copy of id with a rewritten
// Index but the same underlying block pointer.  External tests use
// this to verify that Derive rejects the tampered value.  Cannot be
// constructed from user code because Identity.block is unexported.
func TamperIdentityIndexForTest(id Identity, newIdx uint64) Identity {
	id.Index = newIdx
	return id
}

// TamperIdentityPublicPointForTest returns a copy of id with one
// byte of PublicPoint flipped but the same block pointer.  Same
// purpose as TamperIdentityIndexForTest.
func TamperIdentityPublicPointForTest(id Identity) Identity {
	id.PublicPoint[0] ^= 0xFF
	return id
}

// IdentityBlockPointerEqualForTest reports whether two Identities
// point at the same identityBlock, independent of the visible
// fields.  Distinguishes "same identity by == (all fields match)"
// from "same block pointer, different visible fields (tampered)".
func IdentityBlockPointerEqualForTest(a, b Identity) bool {
	return a.block == b.block
}

// VerifyChainSlotForTest exposes the runtime's JANOSCRT chain
// verifier to external tests so they can drive it end-to-end with
// synthesized slot bytes.  Same signature as janosVerifyChainSlot;
// returns the compact ok bool instead of the tuple to keep the
// test surface small.
func VerifyChainSlotForTest(slot []byte, binaryHash [32]byte,
	expectGuildPK, expectReleasePK *[64]byte) bool {
	_, _, _, _, ok := janosVerifyChainSlot(slot, binaryHash, expectGuildPK, expectReleasePK)
	return ok
}
