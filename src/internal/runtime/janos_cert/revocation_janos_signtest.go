// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build janos_signtest

// Test-only revocation-list mutators.  Only compiled with
// -tags janos_signtest.  Production revocation state is baked into
// revocation.go and edited only via a security-release commit.

package janos_cert

// SetRevokedReleasesForTest swaps in a test-supplied release
// revocation list.  Returns the previous list so the test can defer
// restoring it.  Not safe for concurrent tests — call in serial or
// use t.Parallel discipline.
func SetRevokedReleasesForTest(list []RevocationEntry) []RevocationEntry {
	prev := revokedReleases
	revokedReleases = list
	return prev
}

// SetRevokedUsersForTest — same shape for the user list.
func SetRevokedUsersForTest(list []RevocationEntry) []RevocationEntry {
	prev := revokedUsers
	revokedUsers = list
	return prev
}

// RevocationEntryForTest builds a revocation entry from a signer's
// public key by hashing it — exposes certIDFromPubKey to test code
// without exporting it in the production API.
func RevocationEntryForTest(signerPubKey [32]byte, epoch uint32) RevocationEntry {
	return RevocationEntry{
		SignerKeyID: certIDFromPubKey(signerPubKey),
		RevokeEpoch: epoch,
	}
}

// WildcardEpochForTest exposes the wildcard sentinel for tests.
const WildcardEpochForTest = wildcardRevokeEpoch
