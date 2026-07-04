// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command ceremony runs the one-time JanOS release ceremony:
//
//   1. Fetches the Guild root and Release public keys from their
//      respective KMS resources.
//   2. Has the Guild root sign the Release public key, producing
//      the parent_cert that all colonels of this release will use
//      to prove their Release entry chains back to the Guild.
//   3. Locally sanity-checks the signature before emitting anything.
//   4. Writes a well-formed signet file to stdout, ready to be
//      committed to the JanOS repo root.
//
// Usage:
//
//	export JANOS_GCP_ACCESS_TOKEN=$(gcloud auth application-default print-access-token)
//	go run cmd/janos/ceremony \
//	  --root=gcpkms://projects/PROJECT/locations/LOC/keyRings/guild/cryptoKeys/root/cryptoKeyVersions/1 \
//	  --release=gcpkms://projects/PROJECT/locations/LOC/keyRings/guild/cryptoKeys/ambrosia/cryptoKeyVersions/1 \
//	  --epoch=1 \
//	  > signet
//
// Signing algorithm: ECDSA P-256.  Google Cloud KMS does not support
// HSM protection for Ed25519 keys, so JanOS's family keys live as
// EC_SIGN_P256_SHA256 asymmetric-signing keys with HSM protection.
// The parent_cert baked into every colonel is Guild's P-256 signature
// (r || s) over the Release public key (SHA-256'd once so the
// signature is over the 32-byte digest, matching what the runtime
// verifier will compute).
//
// The ceremony is IRREVERSIBLE in the sense that the resulting
// parent_cert IS the chain of trust for this family line.  Losing
// the signet after this step means losing the ability to produce
// new colonels others recognize; recovery requires cutting a new
// family line (new Guild root, new signature ceremony) and
// convincing consumers to trust the new root.
//
// The root's signature over release_pubkey is what makes revocation
// possible: to revoke a Release key, publish a new runtime release
// whose baked-in revocation list includes the (SHA-256(release_pk),
// release_epoch) tuple.  The Guild root itself is never revoked;
// compromise of the Guild key means cutting a new family line.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"

	"cmd/janos/diviner"
	_ "cmd/janos/diviner/gcpkms" // registers "gcpkms" scheme
)

func main() {
	root := flag.String("root", "", "KMS URL of the Guild root signing key (never revoked, non-expiring)")
	release := flag.String("release", "", "KMS URL of THIS release's signing key")
	epoch := flag.Uint("epoch", 1, "revocation epoch for the release key (increment when running a new ceremony under the same family line)")
	verbose := flag.Bool("v", false, "print public keys to stderr for out-of-band verification")
	flag.Parse()

	if *root == "" || *release == "" {
		fatal("both --root and --release are required (both should be gcpkms:// URLs)")
	}

	rootDiviner, err := diviner.Open(*root)
	if err != nil {
		fatal("opening root: %v", err)
	}
	releaseDiviner, err := diviner.Open(*release)
	if err != nil {
		fatal("opening release: %v", err)
	}

	fmt.Fprintln(os.Stderr, "fetching root public key from KMS...")
	rootPK, err := rootDiviner.PublicKey()
	if err != nil {
		fatal("fetching root public key: %v", err)
	}
	fmt.Fprintln(os.Stderr, "fetching release public key from KMS...")
	releasePK, err := releaseDiviner.PublicKey()
	if err != nil {
		fatal("fetching release public key: %v", err)
	}

	if rootPK == releasePK {
		fatal("root and release resolved to the same public key — check your KMS URLs; they must name distinct keys")
	}

	if *verbose {
		fmt.Fprintf(os.Stderr, "\nroot public key:    %x\n", rootPK)
		fmt.Fprintf(os.Stderr, "release public key: %x\n\n", releasePK)
		fmt.Fprintln(os.Stderr, "VERIFY these against the values returned by")
		fmt.Fprintln(os.Stderr, "  gcloud kms keys versions get-public-key --key=root ...")
		fmt.Fprintln(os.Stderr, "  gcloud kms keys versions get-public-key --key=<release> ...")
		fmt.Fprintln(os.Stderr, "BEFORE using the resulting signet.")
		fmt.Fprintln(os.Stderr, "If they don't match, ABORT and check your KMS URLs.")
		fmt.Fprintln(os.Stderr)
	}

	// The critical ceremony step: root signs SHA-256(release_pubkey).
	// The runtime verifier hashes the parent's pubkey the same way
	// before calling ECDSA verify, so both sides agree on the message
	// under the signature.
	fmt.Fprintln(os.Stderr, "requesting root to sign SHA-256(release_pubkey)...")
	digest := sha256.Sum256(releasePK[:])
	parentCert, err := rootDiviner.Sign(digest)
	if err != nil {
		fatal("root signing release pubkey digest: %v", err)
	}

	// Local sanity check: verify the signature against the root's
	// declared public key BEFORE emitting the signet.  A KMS
	// misconfiguration (wrong algorithm, wrong key version, cached
	// stale pubkey) would show up here rather than during a downstream
	// build when the toolchain refuses to accept the chain.
	if !verifyLocal(rootPK, digest, parentCert) {
		fatal("SANITY CHECK FAILED — root's signature over SHA-256(release_pubkey) does not verify with root's own public key.  KMS misconfiguration?")
	}

	// Emit the signet.
	out := os.Stdout
	fmt.Fprintln(out, "# JanOS signet — release ceremony output")
	fmt.Fprintln(out, "#")
	fmt.Fprintln(out, "# This file was generated by the release-ceremony tool.  It contains")
	fmt.Fprintln(out, "# the authoritative chain of trust for this JanOS release.  Losing it")
	fmt.Fprintln(out, "# means losing the ability to produce colonels other JanOS runtimes")
	fmt.Fprintln(out, "# in this family line will recognize.")
	fmt.Fprintln(out, "#")
	fmt.Fprintln(out, "# Commit this file to source control.  All values are public — no")
	fmt.Fprintln(out, "# secret material is embedded here.  The KMS URLs are references,")
	fmt.Fprintln(out, "# and the parent_cert is an ECDSA P-256 signature that anyone with")
	fmt.Fprintln(out, "# the root public key can verify.")
	fmt.Fprintln(out)

	fmt.Fprintf(out, "guild_pubkey        = %s\n", hex.EncodeToString(rootPK[:]))
	fmt.Fprintf(out, "guild_diviner       = %s\n", *root)
	fmt.Fprintf(out, "release_pubkey      = %s\n", hex.EncodeToString(releasePK[:]))
	fmt.Fprintf(out, "release_diviner     = %s\n", *release)
	fmt.Fprintf(out, "release_parent_cert = %s\n", hex.EncodeToString(parentCert[:]))
	fmt.Fprintf(out, "release_epoch       = %d\n", *epoch)

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "release ceremony complete; signet emitted to stdout")
	fmt.Fprintln(os.Stderr, "next step: redirect stdout to the repo-root `signet` file")
}

// verifyLocal wraps stdlib crypto/ecdsa to check that (r, s) is
// a valid signature over digest under the P-256 pubkey X||Y.  The
// ceremony runs in a stock-Go environment, so we can lean on stdlib
// here rather than the runtime's pure-Go verifier.
func verifyLocal(pubKey [64]byte, digest [32]byte, sig [64]byte) bool {
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(pubKey[:32]),
		Y:     new(big.Int).SetBytes(pubKey[32:]),
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, digest[:], r, s)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "release-ceremony: "+format+"\n", args...)
	os.Exit(1)
}
