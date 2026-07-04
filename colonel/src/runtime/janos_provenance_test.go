// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"runtime"
	"sync"
	"testing"
)

// TestInstanceIDAssigned confirms schedinit populates the process's
// instance ID with non-zero random bytes.  Every real JanOS process
// carries an instance ID from before user init runs.
func TestInstanceIDAssigned(t *testing.T) {
	p := runtime.CurrentProvenance()
	if p.InstanceID == (runtime.Provenance{}).InstanceID {
		t.Fatal("instance ID was not assigned during schedinit — got all-zero bytes")
	}
}

// TestBinaryHashAssigned confirms schedinit self-hashed the running
// binary on platforms that have a native reader (linux, darwin).  On
// stub-covered platforms it will still be zero and the test skips.
func TestBinaryHashAssigned(t *testing.T) {
	p := runtime.CurrentProvenance()
	if p.BinaryHash == (runtime.Provenance{}).BinaryHash {
		if p.TrustLevel != runtime.TrustNone {
			t.Fatalf("BinaryHash is zero but TrustLevel is %s; expected TrustNone", p.TrustLevel)
		}
		t.Skip("no self-hash reader on this platform yet — BinaryHash is zero, TrustLevel is TrustNone (expected)")
	}
	if p.TrustLevel < runtime.TrustSelfAttested {
		t.Fatalf("BinaryHash is populated but TrustLevel is %s; expected at least TrustSelfAttested", p.TrustLevel)
	}
}

// TestCurrentProvenanceInheritance verifies both fields inherit across
// go func().
func TestCurrentProvenanceInheritance(t *testing.T) {
	saved := runtime.CurrentProvenance()
	defer runtime.SetCurrentProvenanceForTest(saved)

	want := runtime.Provenance{
		InstanceID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		BinaryHash: sha256Fixture("binary-hash-fixture"),
		TrustLevel: runtime.TrustHardwareAttested,
	}
	runtime.SetCurrentProvenanceForTest(want)

	var wg sync.WaitGroup
	var got runtime.Provenance
	wg.Add(1)
	go func() {
		defer wg.Done()
		got = runtime.CurrentProvenance()
	}()
	wg.Wait()

	if got != want {
		t.Fatalf("child goroutine did not inherit provenance:\nwant %+v\ngot  %+v", want, got)
	}
}

// TestCurrentProvenanceInheritanceNested — grandchild inherits through
// child, confirming inheritance chains across arbitrary depth.
func TestCurrentProvenanceInheritanceNested(t *testing.T) {
	saved := runtime.CurrentProvenance()
	defer runtime.SetCurrentProvenanceForTest(saved)

	var want runtime.Provenance
	copy(want.InstanceID[:], []byte{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0})
	want.BinaryHash = sha256Fixture("root-binary")
	want.TrustLevel = runtime.TrustColonelAttested
	runtime.SetCurrentProvenanceForTest(want)

	var wg sync.WaitGroup
	var grandchild runtime.Provenance
	wg.Add(1)
	go func() {
		defer wg.Done()
		var inner sync.WaitGroup
		inner.Add(1)
		go func() {
			defer inner.Done()
			grandchild = runtime.CurrentProvenance()
		}()
		inner.Wait()
	}()
	wg.Wait()

	if grandchild != want {
		t.Fatalf("grandchild goroutine did not inherit provenance:\nwant %+v\ngot  %+v", want, grandchild)
	}
}

func TestTrustLevelString(t *testing.T) {
	cases := []struct {
		lvl  runtime.TrustLevel
		want string
	}{
		{runtime.TrustNone, "none"},
		{runtime.TrustSelfAttested, "self-attested"},
		{runtime.TrustJanosReleased, "janos-released"},
		{runtime.TrustHardwareAttested, "hardware-attested"},
		{runtime.TrustColonelAttested, "colonel-attested"},
		{runtime.TrustLevel(200), "unknown"},
	}
	for _, c := range cases {
		if got := c.lvl.String(); got != c.want {
			t.Errorf("TrustLevel(%d).String() = %q; want %q", c.lvl, got, c.want)
		}
	}
}

// TestCertificateAccessorsZero: before any cert is populated, the
// accessors return the zero value and UserCert reports absent.
func TestCertificateAccessorsZero(t *testing.T) {
	runtime.SetJanosCertificatesForTest(runtime.Certificate{}, runtime.Certificate{}, nil)
	if g := runtime.GuildCert(); g != (runtime.Certificate{}) {
		t.Errorf("GuildCert non-zero after clear: %+v", g)
	}
	if r := runtime.ReleaseCert(); r != (runtime.Certificate{}) {
		t.Errorf("ReleaseCert non-zero after clear: %+v", r)
	}
	if _, ok := runtime.UserCert(); ok {
		t.Error("UserCert reports present after clear")
	}
}

// TestSetJanosCertificatesForTest populates then reads back the
// three certs.  Also verifies Provenance carries the compact SHA-256
// IDs of Guild/Release signer keys and TrustLevel bumps to
// TrustJanosReleased.
func TestSetJanosCertificatesForTest(t *testing.T) {
	savedGuild := runtime.GuildCert()
	savedRelease := runtime.ReleaseCert()
	savedUser, savedHasUser := runtime.UserCert()
	savedProv := runtime.CurrentProvenance()
	defer func() {
		var userPtr *runtime.Certificate
		if savedHasUser {
			userPtr = &savedUser
		}
		runtime.SetJanosCertificatesForTest(savedGuild, savedRelease, userPtr)
		runtime.SetCurrentProvenanceForTest(savedProv)
	}()

	guild := runtime.Certificate{
		Level:        0,
		SignerPubKey: [64]byte{0x01, 0x02, 0x03},
	}
	release := runtime.Certificate{
		Level:        1,
		SignerPubKey: [64]byte{0x11, 0x12, 0x13},
	}
	user := runtime.Certificate{
		Level:        2,
		SignerPubKey: [64]byte{0x21, 0x22, 0x23},
	}
	runtime.SetJanosCertificatesForTest(guild, release, &user)

	if got := runtime.GuildCert(); got != guild {
		t.Errorf("GuildCert readback mismatch\nwant %+v\ngot  %+v", guild, got)
	}
	if got := runtime.ReleaseCert(); got != release {
		t.Errorf("ReleaseCert readback mismatch\nwant %+v\ngot  %+v", release, got)
	}
	gotUser, ok := runtime.UserCert()
	if !ok {
		t.Fatal("UserCert reports absent after setting")
	}
	if gotUser != user {
		t.Errorf("UserCert readback mismatch\nwant %+v\ngot  %+v", user, gotUser)
	}

	p := runtime.CurrentProvenance()
	if p.TrustLevel != runtime.TrustJanosReleased {
		t.Errorf("TrustLevel: want TrustJanosReleased, got %s", p.TrustLevel)
	}
	// GuildCertID is SHA-256 of guild.SignerPubKey; can't reproduce
	// that exactly without importing janos_hash here, but we CAN
	// verify it's nonzero and distinct from ReleaseCertID.
	if p.GuildCertID == (runtime.Provenance{}).GuildCertID {
		t.Error("GuildCertID zero after cert set")
	}
	if p.ReleaseCertID == (runtime.Provenance{}).ReleaseCertID {
		t.Error("ReleaseCertID zero after cert set")
	}
	if p.GuildCertID == p.ReleaseCertID {
		t.Error("GuildCertID == ReleaseCertID (distinct signer keys should hash differently)")
	}
}

// TestCertIDsInheritance: after setting certs on the parent, a
// spawned goroutine inherits the same IDs and TrustLevel.
func TestCertIDsInheritance(t *testing.T) {
	saved := runtime.CurrentProvenance()
	savedGuild, savedRelease := runtime.GuildCert(), runtime.ReleaseCert()
	savedUser, savedHasUser := runtime.UserCert()
	defer func() {
		var userPtr *runtime.Certificate
		if savedHasUser {
			userPtr = &savedUser
		}
		runtime.SetJanosCertificatesForTest(savedGuild, savedRelease, userPtr)
		runtime.SetCurrentProvenanceForTest(saved)
	}()

	guild := runtime.Certificate{SignerPubKey: [64]byte{0xaa}}
	release := runtime.Certificate{SignerPubKey: [64]byte{0xbb}}
	runtime.SetJanosCertificatesForTest(guild, release, nil)
	parent := runtime.CurrentProvenance()

	var wg sync.WaitGroup
	var child runtime.Provenance
	wg.Add(1)
	go func() {
		defer wg.Done()
		child = runtime.CurrentProvenance()
	}()
	wg.Wait()

	if child != parent {
		t.Fatalf("child did not inherit cert IDs / trust level:\nparent %+v\nchild  %+v", parent, child)
	}
}

// TestJanosSHA256KnownAnswer verifies the runtime-internal SHA-256
// against NIST test vectors.  If this ever fails, everything else is
// suspect — the whole self-attestation story hinges on this hash
// being correct.
func TestJanosSHA256KnownAnswer(t *testing.T) {
	cases := []struct {
		in   string
		want [32]byte
	}{
		{"", [32]byte{
			0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
			0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
			0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
			0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
		}},
		{"abc", [32]byte{
			0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
			0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
			0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
			0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
		}},
		{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", [32]byte{
			0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
			0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
			0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
			0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
		}},
	}
	for _, c := range cases {
		got := runtime.JanosSHA256ForTest([]byte(c.in))
		if got != c.want {
			t.Errorf("JanosSHA256(%q):\nwant %x\ngot  %x", c.in, c.want, got)
		}
	}
}

// TestJanosSHA512KnownAnswer verifies the runtime-internal SHA-512
// against three NIST test vectors (FIPS 180-4 examples).  Ed25519
// verification depends on SHA-512 being correct, so we vet it before
// building on top.
func TestJanosSHA512KnownAnswer(t *testing.T) {
	cases := []struct {
		in   string
		want [64]byte
	}{
		{"", [64]byte{
			0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
			0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
			0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
			0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
			0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
			0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
			0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
			0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
		}},
		{"abc", [64]byte{
			0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
			0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
			0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
			0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
			0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
			0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
			0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
			0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
		}},
		{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", [64]byte{
			0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda,
			0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
			0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1,
			0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
			0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4,
			0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
			0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54,
			0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09,
		}},
	}
	for _, c := range cases {
		got := runtime.JanosSHA512ForTest([]byte(c.in))
		if got != c.want {
			t.Errorf("JanosSHA512(%q):\nwant %x\ngot  %x", c.in, c.want, got)
		}
	}
}

// TestJanosVerifyCertSlotBootstrapSkips: on a bootstrap runtime (no
// baked-in expected Guild/Release keys), schedinit's cert-slot check
// runs but returns without changing TrustLevel — the runtime hasn't
// been assigned a family line so there's nothing to enforce.
//
// This test runs against a stock-Go-built janos toolchain (which is
// what `./make.bash` produces for the current runtime).  All expected
// keys are zero, so the hybrid gate takes the bootstrap-permissive
// path and TrustLevel stays at whatever the self-hash pass set.
func TestJanosVerifyCertSlotBootstrapSkips(t *testing.T) {
	p := runtime.CurrentProvenance()
	// At this point schedinit has run.  On darwin/arm64 the self-hash
	// pass sets TrustSelfAttested; on stub platforms it stays at
	// TrustNone.  What we DON'T want to see is TrustJanosReleased,
	// which would mean the runtime somehow ran the cert verifier on
	// an undivined bootstrap binary.
	if p.TrustLevel == runtime.TrustJanosReleased {
		t.Errorf("bootstrap binary reported TrustJanosReleased; expected lower level")
	}
}


// sha256Fixture returns a fixed byte pattern derived from name.
// It is not an actual SHA-256 — provenance-inheritance tests do not
// care about the hash's cryptographic origin, only that distinct
// labels produce distinct byte patterns.
func sha256Fixture(name string) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = byte(i) ^ byte(name[i%len(name)])
	}
	return out
}
