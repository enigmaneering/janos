# JanOS additions

A cheat sheet of what JanOS adds on top of stock Go, meant for a
contributor who already knows Go and just needs to know where this
tree differs.  Read this first, then read the specific runtime files
each section points to.

JanOS is a fork of [tamago-go](https://github.com/usbarmory/tamago-go),
which is itself a fork of upstream Go.  So the divergence is layered:

```
upstream Go  →  tamago-go  →  JanOS
```

## From upstream Go, tamago-go adds

- **`GOOS=tamago`** — a synthetic OS target that produces a bare-metal
  binary with no kernel dependency.  Boots directly on hardware or in
  a hypervisor.
- **Bare-metal ports** for `amd64`, `arm`, `arm64`, `loong64`,
  `riscv64`, and (via `GOOS=tamago`) a shared runtime that talks to
  a board-support package instead of syscalls.
- **A userspace-only allocator** — no `mmap` against a kernel; the
  runtime owns physical memory directly.
- **Board packages** — Raspberry Pi 5, USB armory Mk II, others.
- Various removals: no `os/exec`, no dynamic linking, no cgo host,
  etc.  See tamago's upstream README for the full list.

Tamago's additions are self-contained to the runtime and toolchain;
Go source that compiles on stock Go generally compiles on tamago-go
too (minus what tamago removed).

## What JanOS adds on top of tamago-go

Each item names the file(s) to read for the actual implementation.

### 1. Provenance on every goroutine
- `src/runtime/janos_provenance.go`, `src/runtime/janos_provenance_g.go`
- Every `runtime.g` carries a `provenance` sub-struct: `TrustLevel`,
  `BinaryHash`, `InstanceID`, `GuildCertID`, `ReleaseCertID`.
- Provenance is **inherited** through `newproc1`: a child goroutine's
  identity descends from its parent's, so provenance tracks call
  lineage without user cooperation.
- `runtime.CurrentProvenance()` and friends give userspace read-only
  access.  There is deliberately no setter: production code cannot
  forge its own identity.

### 2. Divined boot (KMS-signed identity chain)
- Runtime: `src/runtime/janos_selfhash*.go`,
  `src/runtime/janos_cert_slot.go`, `src/runtime/janos_cert_verify.go`
- Toolchain: `src/cmd/link/internal/ld/janos_diviner.go`,
  `src/cmd/janos/{ceremony,diviner}/**`
- At link time, a **diviner pass** computes SHA-256 of the assembled
  binary with a canonical zeroing (JANOSCRT slot + expected-pubkey
  positions + Go build ID + Mach-O `LC_CODE_SIGNATURE`/`LC_UUID` +
  ELF `.note.gnu.build-id` are all zeroed before hashing), then asks
  a KMS-backed signer (currently GCP KMS via `gcpkms://` URLs, an
  interface at `src/cmd/janos/diviner/diviner.go` allows other
  backends) to sign that digest.  Signature + public keys are
  written into a fixed 2 KiB **JANOSCRT slot** in the binary.
- At runtime `schedinit`, the same canonical hash is recomputed
  from the on-disk image, the Guild-signed Release pubkey is
  verified, then the Release-signed binary hash is verified.  On
  success `TrustLevel` becomes `TrustJanosReleased`.  On failure
  the runtime `throw`s — a divined binary refuses to keep running
  if its chain doesn't verify.
- Two runtime-carried keys make this all self-contained:
  `janosExpectedGuildPubKey` (the family-line root of trust) and
  `janosExpectedReleasePubKey` (the specific signer).  When both
  hold the `"UNDIVINED-…"` sentinel, the runtime is in
  **bootstrap mode** — verify is skipped, `TrustSelfAttested`
  stays as the ceiling.  This is what a stock-Go-built JanOS
  looks like, and it is a completely functional runtime.
- Cross-platform E2E verified on darwin/arm64, linux/arm64,
  and windows/arm64.

### 3. Runtime crypto (no stdlib dependency)
- `src/runtime/janos_hash/` (SHA-256, SHA-512)
- `src/runtime/janos_p256_*.go` (ECDSA P-256: field, scalar, points,
  verify)
- The runtime cannot import `crypto/*` because those packages import
  back into runtime-adjacent things.  Divined boot needs SHA-256
  and ECDSA verify **before** the standard library is safe to
  reach, so the runtime carries its own implementations.  These are
  vendored, minimal, and covered by RFC test vectors.

### 4. Sweep-time memory sanitization (zero-on-free)
- `src/runtime/janos_sanitize.go`, the small-object hook inline in
  `src/runtime/mgcsweep.go` (in the "find newly freed objects"
  loop), and the stack hook in `src/runtime/stack.go` (in
  `stackfree`).
- Stock Go leaves freed heap slots and freed stack pages un-zeroed
  until the next allocator hands them out.  JanOS memclr's them
  unconditionally at the moment they leave user-visible lifetime:
  - Small-object heap slots: sweep-time, folded into Go's existing
    "find newly freed objects" iteration so we walk the mark bitmap
    once.
  - Large-object heap spans: `janosSanitizeLargeSpan` right before
    `mheap_.freeSpan` returns pages to the heap.
  - Goroutine stacks: `janosSanitizeStack` at the top of `stackfree`,
    before the stack goes to `stackpool` / `stackcache` /
    `stackLarge` / `freeManual`.  Covers both the small-stack and
    large-stack paths, and (transitively) the abandoned old stack
    on `copystack` and `shrinkstack`.
  - User arena chunks: **no JanOS hook needed** — `arena.go`
    already `sysFault`s a chunk (unmaps the pages) before it
    enters the quarantine list, and `allocUserArenaChunk` calls
    `sysMap` on reuse, so the kernel guarantees fresh zero-filled
    pages.
- Invariants:
  - Freed heap memory always reads as zero.
  - Freed stack memory is always zero before another goroutine can
    receive that range from the stack pool.
- Overhead: ≈ 2 % of one core under typical server allocation
  rates for heap sanitize; stack sanitize is unmeasurable.  Not
  tunable; JanOS binaries always sanitize.
- Does *not* cover CPU registers — a `Secret[T]` container plus
  optional compiler-directed function-level scrubbing is the
  follow-up plan there.

### 5. Toolchain plumbing for the above
- `-janos-diviner=<url>` and `-janos-signet=<path>` `cmd/link` flags.
- `cmd/janos/ceremony` — one-shot tool that produces the signet
  (Guild+Release pubkeys and Guild's signature over the Release
  pubkey).  The signet has no secrets and is committed at repo
  root.
- `cmd/janos/inspect` — dumps the JANOSCRT slot from a binary.
- `cmd/janos/diviner/gcpkms` — the current KMS backend.  Reads
  its OAuth bearer from the `JANOS_GCP_ACCESS_TOKEN` env var
  (populated by `gcloud auth application-default print-access-token`
  during a local build).

## What JanOS intentionally does NOT change

- Language spec, generics, module system, `go` command UX.  Nothing
  a JanOS binary does is visible to user Go code as new syntax or
  new stdlib packages.  The whole surface is runtime-implicit or
  toolchain-implicit.
- Compatibility with stock Go source.  A Go program that compiled
  under tamago-go compiles under JanOS with the same output shape,
  plus divination if the operator passes the flags.

## Where to go next

- **`README.md`** — high-level project pitch.
- **`README.upstream.md`** — tamago's own docs, preserved.
- **`CONTRIBUTING.md`** — patch flow.
- **`SECURITY.md`** — reporting.
