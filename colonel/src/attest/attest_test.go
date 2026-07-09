// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package attest_test

import (
	"attest"
	"errors"
	"testing"
)

// TestProbeAvailableAgree checks the invariant that ties the two
// entry points together: Available() is true exactly when Probe()
// returns a nil error.  This holds on every platform regardless of
// whether hardware is actually present, so it is the load-bearing
// contract test.
func TestProbeAvailableAgree(t *testing.T) {
	_, err := attest.Probe()
	avail := attest.Available()
	if avail != (err == nil) {
		t.Fatalf("Available()=%v but Probe() err=%v — the two must agree", avail, err)
	}
}

// TestProbeContract validates the shape of every possible Probe
// outcome, again without requiring any particular hardware:
//
//   - success → non-None mechanism;
//   - ErrUnavailable → zero-value Capability;
//   - present-but-inaccessible → non-None mechanism AND a non-nil,
//     non-ErrUnavailable error.
func TestProbeContract(t *testing.T) {
	cap, err := attest.Probe()
	switch {
	case err == nil:
		if cap.Mechanism == attest.MechanismNone {
			t.Errorf("Probe() succeeded but Mechanism is None: %+v", cap)
		}
	case errors.Is(err, attest.ErrUnavailable):
		if cap != (attest.Capability{}) {
			t.Errorf("Probe() returned ErrUnavailable but a non-zero Capability: %+v", cap)
		}
	default:
		// Present but not reachable (e.g. a TPM device the process
		// cannot open).  The facility must still be identified.
		if cap.Mechanism == attest.MechanismNone {
			t.Errorf("Probe() reported an access error but no Mechanism: err=%v cap=%+v", err, cap)
		}
	}
}

func TestMechanismString(t *testing.T) {
	cases := map[attest.Mechanism]string{
		attest.MechanismNone:          "none",
		attest.MechanismTPM20:         "TPM 2.0",
		attest.MechanismSecureEnclave: "Secure Enclave",
		attest.Mechanism(200):         "unknown",
	}
	for m, want := range cases {
		if got := m.String(); got != want {
			t.Errorf("Mechanism(%d).String() = %q, want %q", m, got, want)
		}
	}
}

func TestCapabilityString(t *testing.T) {
	c := attest.Capability{
		Mechanism: attest.MechanismTPM20,
		Route:     "/dev/tpmrm0",
		Vendor:    "STMicro",
		Version:   "TPM 2.0",
	}
	got := c.String()
	// Spot-check that each populated field surfaces; exact formatting
	// is not contractual.
	for _, want := range []string{"TPM 2.0", "/dev/tpmrm0", "STMicro"} {
		if !contains(got, want) {
			t.Errorf("Capability.String() = %q, missing %q", got, want)
		}
	}
	if empty := (attest.Capability{}).String(); empty != "none" {
		t.Errorf("zero Capability.String() = %q, want %q", empty, "none")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestProbeReport logs what this host actually detected.  It never
// fails — it exists so `go test -v ./attest` shows a human the real
// result on whatever machine runs it.
func TestProbeReport(t *testing.T) {
	cap, err := attest.Probe()
	switch {
	case err == nil:
		t.Logf("hardware root of trust: %s", cap)
	case errors.Is(err, attest.ErrUnavailable):
		t.Logf("no hardware root of trust detected on this host")
	default:
		t.Logf("hardware root of trust present but not reachable: %v", err)
	}
}
