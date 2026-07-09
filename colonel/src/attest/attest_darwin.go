// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin

package attest

import "syscall"

func probe() (Capability, error) {
	// Every Apple Silicon Mac ships a Secure Enclave.  The
	// hw.optional.arm64 sysctl is the canonical "is this Apple
	// Silicon" signal — 1 on arm64 Apple hardware, absent or 0
	// otherwise.
	if v, err := syscall.SysctlUint32("hw.optional.arm64"); err == nil && v == 1 {
		return Capability{
			Mechanism: MechanismSecureEnclave,
			Route:     "Secure Enclave",
			Vendor:    "Apple",
			Version:   "Apple Silicon",
		}, nil
	}
	// Intel Macs carry a Secure Enclave only when a T2 coprocessor is
	// present.  Reliably detecting the T2 needs IORegistry access, not
	// a sysctl, so rather than guess we report unavailable here.  T2
	// detection is a follow-up; every arm64 Mac — the target the
	// colonel fleet runs on — is already covered above.
	return Capability{}, ErrUnavailable
}

func available() bool {
	_, err := probe()
	return err == nil
}
