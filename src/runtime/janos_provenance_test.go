// Copyright 2026 The Enigmaneering Authors.
// SPDX-License-Identifier: BSD-3-Clause

package runtime_test

import (
	"runtime"
	"sync"
	"testing"
)

func TestCurrentProvenanceZero(t *testing.T) {
	saved := runtime.CurrentProvenance()
	defer runtime.SetCurrentProvenance(saved)

	runtime.SetCurrentProvenance(runtime.Provenance{})
	got := runtime.CurrentProvenance()
	if got != (runtime.Provenance{}) {
		t.Fatalf("expected zero-value provenance, got %+v", got)
	}
	if got.TrustLevel != runtime.TrustNone {
		t.Fatalf("zero-value TrustLevel: expected TrustNone (%d), got %d (%s)",
			runtime.TrustNone, got.TrustLevel, got.TrustLevel)
	}
}

func TestCurrentProvenanceInheritance(t *testing.T) {
	saved := runtime.CurrentProvenance()
	defer runtime.SetCurrentProvenance(saved)

	want := runtime.Provenance{
		SignerID:   sha256Fixture("signer-alpha"),
		BinaryHash: sha256Fixture("binary-hash-fixture"),
		TrustLevel: runtime.TrustHardwareAttested,
	}
	runtime.SetCurrentProvenance(want)

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

func TestCurrentProvenanceInheritanceNested(t *testing.T) {
	saved := runtime.CurrentProvenance()
	defer runtime.SetCurrentProvenance(saved)

	want := runtime.Provenance{
		SignerID:   sha256Fixture("root"),
		BinaryHash: sha256Fixture("root-binary"),
		TrustLevel: runtime.TrustColonelAttested,
	}
	runtime.SetCurrentProvenance(want)

	var wg sync.WaitGroup
	var childOfChild runtime.Provenance
	wg.Add(1)
	go func() {
		defer wg.Done()
		var inner sync.WaitGroup
		inner.Add(1)
		go func() {
			defer inner.Done()
			childOfChild = runtime.CurrentProvenance()
		}()
		inner.Wait()
	}()
	wg.Wait()

	if childOfChild != want {
		t.Fatalf("grandchild goroutine did not inherit provenance:\nwant %+v\ngot  %+v", want, childOfChild)
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
// It is not an actual SHA-256 — provenance tests do not care about the
// hash's cryptographic origin, only that distinct labels produce
// distinct byte patterns.
func sha256Fixture(name string) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = byte(i) ^ byte(name[i%len(name)])
	}
	return out
}
