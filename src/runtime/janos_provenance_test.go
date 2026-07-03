// Copyright 2026 The Enigmaneering Authors.
// SPDX-License-Identifier: BSD-3-Clause

package runtime_test

import (
	"runtime"
	"sync"
	"testing"
)

// TestInstanceIDAssigned confirms schedinit populates the process's
// instance ID with non-zero random bytes. Every real JanOS process
// carries an instance ID from before user init runs.
func TestInstanceIDAssigned(t *testing.T) {
	p := runtime.CurrentProvenance()
	if p.InstanceID == (runtime.Provenance{}).InstanceID {
		t.Fatal("instance ID was not assigned during schedinit — got all-zero bytes")
	}
}

// TestRootBinaryAttestation exercises the boot-time setter path,
// checks the once-guard, and verifies that InstanceID is preserved
// across the attestation.
func TestRootBinaryAttestation(t *testing.T) {
	saved := runtime.CurrentProvenance()
	defer runtime.SetCurrentProvenanceForTest(saved)
	defer runtime.ResetRootAttestForTest()
	runtime.ResetRootAttestForTest()

	before := runtime.CurrentProvenance()
	hash := sha256Fixture("bootstrap-binary")

	runtime.SetRootBinaryAttestation(hash, runtime.TrustSelfAttested)

	after := runtime.CurrentProvenance()
	if after.BinaryHash != hash {
		t.Errorf("BinaryHash: want %x, got %x", hash, after.BinaryHash)
	}
	if after.TrustLevel != runtime.TrustSelfAttested {
		t.Errorf("TrustLevel: want %s, got %s", runtime.TrustSelfAttested, after.TrustLevel)
	}
	if after.InstanceID != before.InstanceID {
		t.Errorf("InstanceID mutated by SetRootBinaryAttestation:\nbefore %x\nafter  %x",
			before.InstanceID, after.InstanceID)
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

// sha256Fixture returns a fixed byte pattern derived from name.
// It is not an actual SHA-256 — provenance tests do not care about
// the hash's cryptographic origin, only that distinct labels produce
// distinct byte patterns.
func sha256Fixture(name string) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = byte(i) ^ byte(name[i%len(name)])
	}
	return out
}
