// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !compiler_bootstrap

// Non-bootstrap variant of janosInheritParentKeysIntoOutput.  Uses
// runtime.JanosParentKeys, which is available in a JanOS runtime
// but not in stock Go's — hence the build-tag split with
// janos_inherit_bootstrap.go.

package ld

import "runtime"

// janosInheritParentKeysIntoOutput copies the running cmd/link's own
// expected Guild/Release public keys into the output binary's
// janosExpected*PubKey vars, so a colonel automatically inherits its
// parent janos binary's family line.
//
// Called unconditionally after asmb2, whether or not -janos-diviner
// is set.  If the running janos is undivined (all-zero expected
// keys), this is a no-op — the output stays zero, which the runtime
// treats as permissive/bootstrap mode.  If the running janos is
// divined, the output inherits its keys AND (in the no-diviner case)
// gets a version-0 slot, which the runtime treats as strict-mode-
// but-undivined and refuses to boot.  This is the enforcement rule:
// colonels of a divined janos MUST also be divined.
//
// If -janos-diviner is subsequently invoked, the diviner pass
// overwrites these values with the signet's authoritative keys.
//
// When the output binary does not embed a JanOS runtime (e.g., a
// plugin or an oddly-configured build), the janosExpected* symbols
// won't exist and this function silently returns — no runtime, no
// enforcement, no family line to inherit.
func janosInheritParentKeysIntoOutput(ctxt *Link) {
	guild, release := runtime.JanosParentKeys()
	zero := [64]byte{}
	if guild == zero && release == zero {
		return // bootstrap janos; nothing to inherit
	}
	if guild != zero {
		_ = patchRuntimeKeyIfPresent(ctxt, "runtime.janosExpectedGuildPubKey", guild[:])
	}
	if release != zero {
		_ = patchRuntimeKeyIfPresent(ctxt, "runtime.janosExpectedReleasePubKey", release[:])
	}
}
