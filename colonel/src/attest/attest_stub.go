// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux && !windows && !darwin && !tamago

package attest

// Platforms without a JanOS hardware-attestation route yet (the BSDs,
// Plan 9, wasm, and so on) report no facility.  This keeps the
// package building everywhere the toolchain targets while Available
// and Probe answer honestly for the platform.
func probe() (Capability, error) { return Capability{}, ErrUnavailable }

func available() bool { return false }
