// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package attest is JanOS's hardware-attestation surface: a single,
// OS-neutral way to ask "does this machine have a hardware root of
// trust, and by what means?"
//
// The public API carries no platform bias.  Callers ask the same two
// questions everywhere:
//
//	attest.Available()  // is a hardware root of trust present?
//	attest.Probe()      // describe it, or return ErrUnavailable
//
// and the package decides how to answer by checking the standard
// routes for whatever platform it was built for.  Each platform's
// detection lives in an OS-gated file (attest_linux.go,
// attest_windows.go, attest_darwin.go, …); the routes it checks are a
// platform implementation detail, never something the caller spells.
//
// # What "a hardware root of trust" means here
//
// Two mechanisms are recognized today, described uniformly by the
// Mechanism enum:
//
//   - MechanismTPM20 — a TPM 2.0 device.  On Linux this is the kernel
//     resource-manager character device (/dev/tpmrm0) or the raw
//     device (/dev/tpm0); on Windows it is TPM Base Services (TBS).
//   - MechanismSecureEnclave — an Apple Secure Enclave (Darwin).
//
// A Linux box and a Windows box with TPMs both report MechanismTPM20 —
// the enum classifies the hardware, not the operating system.
//
// # Errors when unavailable
//
// Every entry point fails cleanly when no facility is present: Probe
// returns ErrUnavailable, Available returns false.  A facility that is
// present but not reachable (for example a Linux TPM device the
// process lacks permission to open) is reported as a distinct wrapped
// error, not silently folded into "absent" — the two conditions call
// for different operator responses.
//
// # Scope
//
// This first pass is detection: proving a root of trust exists and
// naming it.  It is the foundation the identity-binding operations
// build on — sealing the process root key (see runtime/janos_identity)
// to the platform's measured boot state, unsealing it at schedinit,
// and producing attestation quotes for remote challengers.  Those
// operations attach to a live session opened against a probed
// facility; they are not part of this first surface.  Detection is
// genuinely complete and useful on its own: a colonel can refuse to
// hold identity on a machine that cannot attest, today, with nothing
// more than Available.
package attest

import "errors"

// ErrUnavailable is returned by Probe when no hardware root of trust
// is present on this platform.  Distinguish it from a
// present-but-inaccessible facility (which Probe reports as a
// different, wrapped error) with errors.Is.
var ErrUnavailable = errors.New("attest: no hardware root of trust available")

// Mechanism classifies the kind of hardware root of trust backing
// attestation.  It describes the hardware, not the operating system:
// TPM-equipped Linux and Windows machines both report MechanismTPM20.
type Mechanism uint8

const (
	// MechanismNone is the zero value: no hardware root of trust.
	MechanismNone Mechanism = iota
	// MechanismTPM20 is a TPM 2.0 device (Linux character device or
	// Windows TBS).
	MechanismTPM20
	// MechanismSecureEnclave is an Apple Secure Enclave (Darwin).
	MechanismSecureEnclave
)

// String returns a human-readable name for the mechanism.
func (m Mechanism) String() string {
	switch m {
	case MechanismNone:
		return "none"
	case MechanismTPM20:
		return "TPM 2.0"
	case MechanismSecureEnclave:
		return "Secure Enclave"
	default:
		return "unknown"
	}
}

// Capability describes the hardware root of trust discovered on this
// platform.  Route names the standard access path that satisfied
// detection (for example "/dev/tpmrm0", "TBS", or "Secure Enclave");
// it is informational — for logging and operator diagnostics — not
// something a caller must interpret to use the facility.  Vendor and
// Version are best-effort and may be empty when the platform does not
// expose them cheaply.
type Capability struct {
	Mechanism Mechanism
	Route     string
	Vendor    string
	Version   string
}

// String renders a Capability as a compact one-line summary.  Version
// and Route are omitted when they merely restate the mechanism name,
// so a TPM reads "TPM 2.0 via /dev/tpmrm0" rather than the redundant
// "TPM 2.0 (TPM 2.0) via /dev/tpmrm0".
func (c Capability) String() string {
	mech := c.Mechanism.String()
	s := mech
	if c.Version != "" && c.Version != mech {
		s += " (" + c.Version + ")"
	}
	if c.Route != "" && c.Route != mech {
		s += " via " + c.Route
	}
	if c.Vendor != "" {
		s += " [" + c.Vendor + "]"
	}
	return s
}

// Available reports whether a hardware root of trust is present and
// usable on this platform.  It is a convenience wrapper over Probe
// that discards the description and any present-but-inaccessible
// detail: Available returns true only when Probe would return a nil
// error.
func Available() bool {
	return available()
}

// Probe discovers this platform's hardware root of trust, checking
// every standard route in order and returning the first that responds.
//
// It returns:
//
//   - a populated Capability and nil error when a usable facility is
//     found;
//   - a zero Capability wrapping ErrUnavailable when none is present;
//   - a partially populated Capability and a non-nil, non-ErrUnavailable
//     error when a facility is present but not reachable (the Mechanism
//     and Route fields identify what was found; the error explains why
//     it could not be opened).
func Probe() (Capability, error) {
	return probe()
}
