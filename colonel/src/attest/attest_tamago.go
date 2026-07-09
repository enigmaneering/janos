// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build tamago

package attest

// Bare-metal attestation is not yet wired for the tamago target.
// Board-support for on-device roots of trust — starting with the
// Raspberry Pi 5 letstrust TPM add-on — reaches the runtime through
// the board tree, which initializes during package init, after the
// schedinit identity mint.  Bringing that path online is its own
// pass; until then the tamago build reports no facility so callers
// degrade cleanly rather than fail to compile.
func probe() (Capability, error) { return Capability{}, ErrUnavailable }

func available() bool { return false }
