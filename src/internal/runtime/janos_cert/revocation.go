// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// JanOS: baked-in revocation list.
//
// Each JanOS runtime carries a list of Release and User certificates
// known to be compromised at the time the runtime was cut.  When
// VerifyChain walks an entry, it looks up (signer_pk_id, revoke_epoch)
// against this list — a match aborts the chain.
//
// The Guild's own root cert is deliberately NOT revocable.  Should
// that key ever be compromised, the correct response is to fork the
// family line under a new Guild root, ship a new runtime, and let the
// old family reach end-of-life via the natural cadence of no-one
// installing new binaries from it.  Making the root revocable would
// introduce a recovery path that itself becomes a target.
//
// This file's contents are the authoritative revocation state for
// this build of the runtime.  When the Guild identifies a compromised
// Release or User key, add its entry here in a security-release
// commit, rebuild, and ship.  Runtime binaries built before that
// point will still accept the compromised key — that's why users
// need to keep their runtimes current.

package janos_cert

// RevocationEntry names a compromised Release or User signer.
type RevocationEntry struct {
	// SignerKeyID is SHA-256 of the compromised signer's Ed25519
	// public key.  Uses the same identifier layout as
	// runtime.Provenance.ReleaseCertID.
	SignerKeyID [32]byte
	// RevokeEpoch matches the entry's revoke_epoch field.  If two
	// entries share a signer key but differ in revoke_epoch, only
	// specific epochs may be listed as revoked (partial key rotation
	// history).  A wildcard entry (RevokeEpoch == ^uint32(0)) revokes
	// every epoch of the signer.
	RevokeEpoch uint32
}

// wildcardRevokeEpoch matches every epoch of a signer's key.  Use
// this when the entire keypair is compromised, not just a specific
// serial.
const wildcardRevokeEpoch uint32 = ^uint32(0)

// revokedReleases lists Release-level signers known compromised as
// of this runtime build.  Empty at time of writing.  When the Guild
// identifies a compromised release key, add its (SignerKeyID,
// RevokeEpoch) here in a security-release commit.
var revokedReleases = []RevocationEntry{
	// Example (commented): revoke every epoch of a hypothetically-
	// compromised release key:
	//   {SignerKeyID: [32]byte{0xde, 0xad, 0xbe, 0xef, ...}, RevokeEpoch: wildcardRevokeEpoch},
}

// revokedUsers lists User-level signers known compromised.  Same
// shape and update discipline as revokedReleases.
var revokedUsers = []RevocationEntry{}

// isRevoked reports whether the given signer key + epoch appears on
// the supplied revocation list.  Uses constant-per-list linear scan;
// for the expected small counts (single digits per runtime release
// at most), this is fine.
func isRevoked(list []RevocationEntry, signerKeyID [32]byte, epoch uint32) bool {
	for _, e := range list {
		if e.SignerKeyID != signerKeyID {
			continue
		}
		if e.RevokeEpoch == wildcardRevokeEpoch || e.RevokeEpoch == epoch {
			return true
		}
	}
	return false
}
