// JanOS: baked-in revocation list.
//
// Each JanOS runtime carries a list of Release and User certificates
// known to be compromised at the time the runtime was cut.  When the
// chain verifier walks an entry, it looks up (signer_pk_id,
// revoke_epoch) against these lists — a match aborts the chain.
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

package runtime

// janosRevocationEntry names a compromised Release or User signer.
type janosRevocationEntry struct {
	// signerKeyID is SHA-256 of the compromised signer's ECDSA P-256
	// public key.  Same identifier layout as Provenance.ReleaseCertID.
	signerKeyID [32]byte
	// revokeEpoch matches the entry's revoke_epoch field.  If two
	// entries share a signer key but differ in revoke_epoch, only
	// specific epochs may be listed as revoked (partial key rotation
	// history).  A wildcard entry (revokeEpoch == ^uint32(0)) revokes
	// every epoch of the signer.
	revokeEpoch uint32
}

// janosWildcardRevokeEpoch matches every epoch of a signer's key.
// Use this when the entire keypair is compromised, not just a
// specific serial.
const janosWildcardRevokeEpoch uint32 = ^uint32(0)

// janosRevokedReleases lists Release-level signers known compromised
// as of this runtime build.  Empty at time of writing.  When the
// Guild identifies a compromised release key, add its (signerKeyID,
// revokeEpoch) here in a security-release commit.
var janosRevokedReleases = []janosRevocationEntry{
	// Example (commented): revoke every epoch of a hypothetically-
	// compromised release key:
	//   {signerKeyID: [32]byte{0xde, 0xad, 0xbe, 0xef, ...}, revokeEpoch: janosWildcardRevokeEpoch},
}

// janosRevokedUsers lists User-level signers known compromised.
// Same shape and update discipline as janosRevokedReleases.
var janosRevokedUsers = []janosRevocationEntry{}

// janosIsRevoked reports whether the given signer key + epoch appears
// on the supplied revocation list.  Linear scan; for the expected
// small counts (single digits per runtime release at most), this is
// fine.
func janosIsRevoked(list []janosRevocationEntry, signerKeyID [32]byte, epoch uint32) bool {
	for _, e := range list {
		if e.signerKeyID != signerKeyID {
			continue
		}
		if e.revokeEpoch == janosWildcardRevokeEpoch || e.revokeEpoch == epoch {
			return true
		}
	}
	return false
}
