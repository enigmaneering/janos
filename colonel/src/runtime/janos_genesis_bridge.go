// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// JanOS: genesis-phase close hook.
//
// runtime/genesis holds the identity-scoped Self of every running
// JanOS goroutine.  For the MAIN goroutine, the genesis "phase"
// spans from schedinit through the end of package init; user code's
// var _ = genesis.Register(...) idiom accumulates Traits during that
// phase, and the runtime closes the phase (freezing Self) at exactly
// one moment: after doInit finishes and before main.main runs.
//
// runtime cannot import runtime/genesis (cycle).  Instead genesis
// registers a close-phase function here via //go:linkname during its
// own package init.  runtime.main invokes it — nil-checked, since
// programs that never import runtime/genesis leave the slot empty.
//
// Only the top-level main phase uses this hook.  SparkAs manages its
// child phases entirely internally: SparkAs mints identity, runs the
// caller's complexInit + traitInits, and calls the internal
// closePhase itself before invoking the child's work function.  The
// runtime hook fires exactly once per program.

package runtime

import _ "unsafe" // for go:linkname

// janosGenesisClosePhaseHook is the callback runtime/genesis installs
// at its own package-init time.  Nil if runtime/genesis is not
// imported; runtime.main nil-checks before invoking.  Not atomic
// because the store happens exactly once during doInit (single-
// threaded init phase) and the load happens exactly once after
// doInit returns.
var janosGenesisClosePhaseHook func()

// janosSetGenesisClosePhaseHook is invoked from runtime/genesis's
// package init via //go:linkname.  Deliberately unexported: this is
// not a general-purpose runtime hook; it is a private bridge from
// genesis to the main-init-done transition.
//
// Do not change signature: used via linkname from runtime/genesis.
//
//go:linkname janosSetGenesisClosePhaseHook
func janosSetGenesisClosePhaseHook(fn func()) {
	janosGenesisClosePhaseHook = fn
}

// janosMaybeCloseGenesisPhase is called from runtime.main between
// doInit and main.main.  A no-op if runtime/genesis is not in the
// program's dependency graph.
func janosMaybeCloseGenesisPhase() {
	if janosGenesisClosePhaseHook != nil {
		janosGenesisClosePhaseHook()
	}
}
