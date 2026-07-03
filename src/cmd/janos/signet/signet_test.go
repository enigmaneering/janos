// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package signet

import (
	"strings"
	"testing"
)

const validSignet = `# comment line
guild_pubkey     = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
guild_signer     = gcpkms://projects/guild-root/locations/global/keyRings/janos/cryptoKeys/root/cryptoKeyVersions/1
release_pubkey   = 2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40
release_signer   = gcpkms://projects/janos/locations/global/keyRings/releases/cryptoKeys/janos-1-26/cryptoKeyVersions/1
release_parent_cert = 41414141414141414141414141414141414141414141414141414141414141414242424242424242424242424242424242424242424242424242424242424242
release_epoch    = 7
`

func TestParseValid(t *testing.T) {
	c, err := Parse(strings.NewReader(validSignet))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.GuildPubKey[0] != 0x01 || c.GuildPubKey[31] != 0x20 {
		t.Errorf("guild_pubkey not decoded: %x", c.GuildPubKey)
	}
	if !strings.HasPrefix(c.GuildSigner, "gcpkms://") {
		t.Errorf("guild_signer: %q", c.GuildSigner)
	}
	if c.ReleasePubKey[0] != 0x21 || c.ReleasePubKey[31] != 0x40 {
		t.Errorf("release_pubkey not decoded: %x", c.ReleasePubKey)
	}
	if c.ReleaseParentCert[0] != 0x41 || c.ReleaseParentCert[63] != 0x42 {
		t.Errorf("release_parent_cert not decoded: %x", c.ReleaseParentCert)
	}
	if c.ReleaseEpoch != 7 {
		t.Errorf("release_epoch: got %d, want 7", c.ReleaseEpoch)
	}
	if err := c.ValidateForBuild(); err != nil {
		t.Errorf("ValidateForBuild rejected a complete config: %v", err)
	}
}

func TestParseRejectFileScheme(t *testing.T) {
	f := `guild_pubkey = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
release_pubkey = 2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40
release_signer = file:///tmp/leaked.pem
release_parent_cert = 41414141414141414141414141414141414141414141414141414141414141414242424242424242424242424242424242424242424242424242424242424242
`
	c, err := Parse(strings.NewReader(f))
	if err != nil {
		t.Fatalf("Parse should accept file:// syntax (validation catches it): %v", err)
	}
	if err := c.ValidateForBuild(); err == nil {
		t.Fatal("ValidateForBuild accepted file:// scheme")
	} else if !strings.Contains(err.Error(), "file://") {
		t.Errorf("wrong error for file scheme: %v", err)
	}
}

func TestParseRejectUnknownScheme(t *testing.T) {
	f := `release_signer = badscheme://whatever
`
	c, _ := Parse(strings.NewReader(f))
	if err := validateSignerScheme(c.ReleaseSigner); err == nil {
		t.Error("validateSignerScheme accepted badscheme://")
	}
}

func TestParseRejectMalformedHex(t *testing.T) {
	f := `guild_pubkey = 0102ZZ04
`
	_, err := Parse(strings.NewReader(f))
	if err == nil {
		t.Fatal("Parse accepted malformed hex")
	}
	if !strings.Contains(err.Error(), "guild_pubkey") {
		t.Errorf("error should identify guild_pubkey line: %v", err)
	}
}

func TestParseRejectWrongLengthHex(t *testing.T) {
	f := `guild_pubkey = 0102
`
	_, err := Parse(strings.NewReader(f))
	if err == nil || !strings.Contains(err.Error(), "want 32") {
		t.Errorf("expected length error, got %v", err)
	}
}

func TestParseIgnoresCommentsAndBlankLines(t *testing.T) {
	f := `

# top comment
guild_pubkey = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20

    # indented comment
release_pubkey = 2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40

`
	c, err := Parse(strings.NewReader(f))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.GuildPubKey == ([32]byte{}) || c.ReleasePubKey == ([32]byte{}) {
		t.Error("keys not decoded")
	}
}

func TestValidateForBuildDetailedErrors(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"missing guild pubkey", `release_pubkey = 2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40
release_signer = gcpkms://x
release_parent_cert = 41414141414141414141414141414141414141414141414141414141414141414242424242424242424242424242424242424242424242424242424242424242`,
			"guild_pubkey"},
		{"missing release signer", `guild_pubkey = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
release_pubkey = 2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40
release_parent_cert = 41414141414141414141414141414141414141414141414141414141414141414242424242424242424242424242424242424242424242424242424242424242`,
			"release_signer"},
		{"missing release parent cert", `guild_pubkey = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
release_pubkey = 2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40
release_signer = gcpkms://ok`,
			"release_parent_cert"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Parse(strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			err = c.ValidateForBuild()
			if err == nil {
				t.Fatal("ValidateForBuild did not error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should mention %q", err.Error(), tc.want)
			}
		})
	}
}
