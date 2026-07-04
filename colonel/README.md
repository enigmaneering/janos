# JanOS

JanOS is Enigmaneering's substrate layer: a fork of [tamago-go](https://github.com/usbarmory/tamago-go) — which is itself a bare-metal Go compiler and runtime from [F-Secure/WithSecure Foundry](https://github.com/usbarmory) — extended with **runtime provenance** so every goroutine, and every binary emitted by the compiler, has a verifiable identity from silicon up.

> **Colonel-as-identified-kernel.** A colonel is an identified kernel: same behaviour and role as a kernel, plus runtime self-attestation (SHA-256 of its own binary) optionally reinforced by hardware attestation (TPM 2.0, SE). Once identity is a property of the running code, "why trust unidentified code?" becomes a question the runtime can answer for every function call.

## Attribution

JanOS stands on two upstreams:

1. **[The Go Programming Language](https://go.dev/)** — © 2009 The Go Authors, BSD-style license. The base compiler, standard library, and runtime.
2. **[tamago-go](https://github.com/usbarmory/tamago-go)** — © F-Secure Foundry (now WithSecure), BSD-style license. The bare-metal Go work: `GOOS=tamago`, ports for amd64/arm/arm64/loong64/riscv64, memory allocator without an OS, board-support tree.

Everything JanOS adds is layered on top of those; we do not claim originality of the base compiler or the tamago port. Upstream's original README is preserved verbatim at [`README.upstream.md`](README.upstream.md).

## What JanOS adds

- **`g.provenance`** — the goroutine descriptor (`runtime.g`) carries a provenance sub-struct: signer identity, binary hash, trust level, and a parent pointer that chains one goroutine's identity into its children's.
- **`runtime.Provenance()`** — public accessor for the current goroutine's identity. Called by the [`mental`](https://git.enigmaneering.org/mental) library to satisfy attestation ceremonies without an OS syscall.
- **`GOOS=tamago` targets that self-attest** — TPM/SE-backed identity checks at boot and at each `exec`-equivalent boundary.
- **Board-support additions** — starting with Raspberry Pi 5 + letstrust TPM add-on, and expanding.

Advanced execution concepts (cortex primitives, resonance-driven scheduling) live one layer up in the [Glitter compiler dialect](https://git.enigmaneering.org/glitter), which emits the plain Go that JanOS runs. Keeping cortical execution out of the kernel keeps JanOS small.

## Fork strategy

We track tamago cadence, not go.googlesource.com cadence — tamago maintainers already rebase onto each stable Go release.

- `origin` — `ssh://git@github.com/enigmaneering/janos.git`
- `upstream` — `ssh://git@github.com/usbarmory/tamago-go.git`
- Base branch — [`upstream/tamago1.26.4`](https://github.com/usbarmory/tamago-go/tree/tamago1.26.4), tamago's stable release branch for Go 1.26.4.
- We track tamago's **release branches**, never `upstream/master`. Tamago publishes one release branch per Go patch version (`tamago1.25.7`, `tamago1.26.0`, `.1`, `.2`, `.3`, `.4`, …), curated by upstream maintainers, backports of security and correctness fixes only. `upstream/master` is where their experimental development happens and is off-limits for JanOS.
- When tamago publishes `tamago1.27.0` (or a newer patch on the current line), we cut a JanOS branch that rebases our commits onto that release branch.
- `golang-mirror` — snapshot of what `origin/master` pointed at before the JanOS reset (plain `golang/go` `master`). Kept as a safety branch; no active development on it.

### Sync workflow

```sh
# 1. Fetch new tamago work.
git fetch upstream

# 2. Rebase JanOS onto tamago's new stable branch.
git checkout master
git rebase upstream/tamago1.27.0   # example — use whatever the newest tamago release is

# 3. Run the tamago build sanity check for at least one target
# (see tamago upstream README for board-specific build recipes).

# 4. Push the rebased master.
git push --force-with-lease origin master
```

Rebases per tamago release land in weeks, not days — the whole runtime touches every one. That cadence is priced in and matches the Enigmaneering roadmap.

## Layout

Upstream's tree is untouched. Files added or extended by JanOS carry a `JanOS` marker in their header comment; everything else is unmodified tamago-go source.

Ports beyond the base Go toolchain live under `src/runtime/*_tamago*.go` and `src/runtime/*_tamago_*.s` — those files come from tamago. JanOS-specific extensions collect under `src/runtime/janos_*.go` and (planned) `src/runtime/provenance_*.go`.

## Building

Base build instructions are inherited from tamago — see [`README.upstream.md`](README.upstream.md) and the tamago project's own docs. Once the JanOS provenance work has landed, the JanOS-specific build (identified colonels for a given board) will document its recipe here.

## License

Everything JanOS inherits from upstream is under the Go BSD-style [`LICENSE`](LICENSE). New files added by JanOS use the same license unless a file header states otherwise.
