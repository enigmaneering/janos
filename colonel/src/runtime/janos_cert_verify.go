// JanOS: JANOSCRT slot decode + chain-of-trust verification.
//
// The slot's wire format is defined in cmd/janos/certslot.  The
// runtime carries the same layout constants here so the verifier
// doesn't depend on that package (which sits above runtime in the
// import graph).  A drift between the two constants would break
// divined-boot verification; the certslot package is the source of
// truth and this file must be kept in sync.  Layout:
//
//	header (16 bytes)
//	  0    8  magic "JANOSCRT"
//	  8    1  version
//	  9    1  entry_count
//	 10    6  reserved
//	entries (8 slots × 200 bytes each = 1600)
//	  0    1  level
//	  1    3  revoke_epoch (little-endian)
//	  4    4  reserved
//	  8   64  signer_pubkey (X || Y)
//	 72   64  parent_cert   (r || s)
//	136   64  signature     (r || s)

package runtime

import "internal/runtime/janos_hash"

// Slot layout constants, matching cmd/janos/certslot.  If those
// values change, this file must move in lockstep.
const (
	janosSlotMagicSize  = 8
	janosSlotVersion    = 1
	janosSlotHeaderSize = 16
	janosEntrySize      = 200
	janosMaxEntries     = 8

	janosLevelGuild   = 0
	janosLevelRelease = 1
	janosLevelUser    = 2
	janosLevelEmpty   = 0xFF
)

// janosCertEntry mirrors the on-wire entry.  Byte-for-byte compatible
// with runtime.Certificate at the field level; we keep them separate
// so decode helpers can populate a scratch value on the stack without
// creating the public Certificate type until we know the entry passed
// verification.
type janosCertEntry struct {
	level       uint8
	revokeEpoch uint32
	signerPK    [64]byte
	parentCert  [64]byte
	signature   [64]byte
}

// decodeJanosEntry unpacks one entry at index idx from the slot.
// Returns the decoded entry and true on success; a false return means
// idx is out of range or the slot is truncated.
func decodeJanosEntry(slot []byte, idx int) (janosCertEntry, bool) {
	if idx < 0 || idx >= janosMaxEntries {
		return janosCertEntry{}, false
	}
	base := janosSlotHeaderSize + idx*janosEntrySize
	if base+janosEntrySize > len(slot) {
		return janosCertEntry{}, false
	}
	var e janosCertEntry
	e.level = slot[base]
	e.revokeEpoch = uint32(slot[base+1]) | uint32(slot[base+2])<<8 | uint32(slot[base+3])<<16
	copy(e.signerPK[:], slot[base+8:base+72])
	copy(e.parentCert[:], slot[base+72:base+136])
	copy(e.signature[:], slot[base+136:base+200])
	return e, true
}

// checkJanosSlotHeader verifies the magic + version at the start of
// the slot.
func checkJanosSlotHeader(slot []byte) bool {
	if len(slot) < janosSlotHeaderSize {
		return false
	}
	magic := [janosSlotMagicSize]byte{'J', 'A', 'N', 'O', 'S', 'C', 'R', 'T'}
	for i := 0; i < janosSlotMagicSize; i++ {
		if slot[i] != magic[i] {
			return false
		}
	}
	return slot[8] == janosSlotVersion
}

// janosCertIDFromPubKey returns SHA-256 of a signer's public key,
// used as a compact stable identifier we can carry in Provenance.
// The argument is a pointer to avoid copying 64 bytes on every call.
func janosCertIDFromPubKey(pk *[64]byte) [32]byte {
	var d janos_hash.SHA256
	d.Reset()
	d.Write(pk[:])
	return d.Sum()
}

// janosVerifyChainSlot walks the slot's entries and validates the
// chain of trust.  Returns (guild, release, user, hasUser, ok).  A
// false ok means the slot is malformed, a required entry is missing,
// a signature failed to verify, or a signer appears on the runtime's
// revocation list.
//
// Guild entry (index 0) is identity-only.  Its SignerPubKey must
// equal expectGuildPK; there is no per-binary signature to check
// because the Guild's private key is offline and endorses this
// release only through the Release entry's ParentCert.
//
// Release entry (index 1) is mandatory.  SignerPubKey must equal
// expectReleasePK.  ParentCert must verify as an ECDSA P-256
// signature by Guild over SHA-256(Release.SignerPubKey).  Signature
// must verify as an ECDSA P-256 signature by Release over binaryHash.
//
// User entry (index 2) is optional.  When present it chains: Release
// signs SHA-256(User.SignerPubKey), User signs binaryHash.
func janosVerifyChainSlot(slot []byte, binaryHash [32]byte,
	expectGuildPK, expectReleasePK *[64]byte,
) (guild, release, user Certificate, hasUser, ok bool) {

	if !checkJanosSlotHeader(slot) {
		return Certificate{}, Certificate{}, Certificate{}, false, false
	}

	// Guild.
	g, decoded := decodeJanosEntry(slot, 0)
	if !decoded || g.level != janosLevelGuild {
		return Certificate{}, Certificate{}, Certificate{}, false, false
	}
	if g.signerPK != *expectGuildPK {
		return Certificate{}, Certificate{}, Certificate{}, false, false
	}
	guild = Certificate{
		Level:        g.level,
		RevokeEpoch:  g.revokeEpoch,
		SignerPubKey: g.signerPK,
		ParentCert:   g.parentCert,
		Signature:    g.signature,
	}

	// Release.
	r, decoded := decodeJanosEntry(slot, 1)
	if !decoded || r.level != janosLevelRelease {
		return Certificate{}, Certificate{}, Certificate{}, false, false
	}
	if r.signerPK != *expectReleasePK {
		return Certificate{}, Certificate{}, Certificate{}, false, false
	}
	// Guild signed SHA-256(Release.SignerPubKey).
	releasePKDigest := janosSha256Of(r.signerPK[:])
	if !janosP256VerifyRS(expectGuildPK, &releasePKDigest, &r.parentCert) {
		return Certificate{}, Certificate{}, Certificate{}, false, false
	}
	// Release signed binaryHash.
	if !janosP256VerifyRS(&r.signerPK, &binaryHash, &r.signature) {
		return Certificate{}, Certificate{}, Certificate{}, false, false
	}
	if janosIsRevoked(janosRevokedReleases, janosCertIDFromPubKey(&r.signerPK), r.revokeEpoch) {
		return Certificate{}, Certificate{}, Certificate{}, false, false
	}
	release = Certificate{
		Level:        r.level,
		RevokeEpoch:  r.revokeEpoch,
		SignerPubKey: r.signerPK,
		ParentCert:   r.parentCert,
		Signature:    r.signature,
	}

	// User (optional).
	u, decoded := decodeJanosEntry(slot, 2)
	if decoded && u.level == janosLevelUser {
		userPKDigest := janosSha256Of(u.signerPK[:])
		if !janosP256VerifyRS(&r.signerPK, &userPKDigest, &u.parentCert) {
			return Certificate{}, Certificate{}, Certificate{}, false, false
		}
		if !janosP256VerifyRS(&u.signerPK, &binaryHash, &u.signature) {
			return Certificate{}, Certificate{}, Certificate{}, false, false
		}
		if janosIsRevoked(janosRevokedUsers, janosCertIDFromPubKey(&u.signerPK), u.revokeEpoch) {
			return Certificate{}, Certificate{}, Certificate{}, false, false
		}
		user = Certificate{
			Level:        u.level,
			RevokeEpoch:  u.revokeEpoch,
			SignerPubKey: u.signerPK,
			ParentCert:   u.parentCert,
			Signature:    u.signature,
		}
		hasUser = true
	}

	return guild, release, user, hasUser, true
}

// janosSha256Of is a small allocation-free wrapper around
// janos_hash.SHA256 for the runtime's verifier.  Returns the digest
// as a value so callers don't need to hold a Sum-side buffer.
func janosSha256Of(msg []byte) [32]byte {
	var d janos_hash.SHA256
	d.Reset()
	d.Write(msg)
	return d.Sum()
}
