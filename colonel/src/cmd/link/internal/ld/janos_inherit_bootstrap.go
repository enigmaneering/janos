//go:build compiler_bootstrap

// Bootstrap-copied cmd/link is compiled by stock Go, whose runtime
// package does not export JanosParentKeys.  During bootstrap the
// stub is a no-op: the bootstrap linker is only used briefly to
// produce the tools of a new toolchain, whose outputs are undivined
// by construction (the bootstrap toolchain has no signet, no KMS
// access, no Guild identity to inherit).  Once the real cmd/link is
// in place, janos_inherit_ok.go's implementation takes over.

package ld

// janosInheritParentKeysIntoOutput is a no-op during bootstrap
// compilation.
func janosInheritParentKeysIntoOutput(ctxt *Link) {}
