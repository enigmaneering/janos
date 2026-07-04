package signet

import (
	"strings"
	"testing"
)

// P-256 pubkeys are 64 bytes (uncompressed X || Y), so signet
// fixtures use 128 hex characters per pubkey field.  The specific
// bytes don't matter for parse tests — we're checking length and
// hex round-tripping, not curve validity.

const guildPubHex64 = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
	"2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"

const releasePubHex64 = "6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80" +
	"818283848586878889808182838485868788898a8b8c8d8e8f909192939495a0"

const parentCertHex64 = "4141414141414141414141414141414141414141414141414141414141414141" +
	"4242424242424242424242424242424242424242424242424242424242424242"

const validSignet = `# comment line
guild_pubkey     = ` + guildPubHex64 + `
guild_diviner     = gcpkms://projects/guild-root/locations/global/keyRings/janos/cryptoKeys/root/cryptoKeyVersions/1
release_pubkey   = ` + releasePubHex64 + `
release_diviner   = gcpkms://projects/janos/locations/global/keyRings/releases/cryptoKeys/janos-1-26/cryptoKeyVersions/1
release_parent_cert = ` + parentCertHex64 + `
release_epoch    = 7
`

func TestParseValid(t *testing.T) {
	c, err := Parse(strings.NewReader(validSignet))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.GuildPubKey[0] != 0x01 || c.GuildPubKey[63] != 0x40 {
		t.Errorf("guild_pubkey not decoded: %x", c.GuildPubKey)
	}
	if !strings.HasPrefix(c.GuildDiviner, "gcpkms://") {
		t.Errorf("guild_diviner: %q", c.GuildDiviner)
	}
	if c.ReleasePubKey[0] != 0x61 || c.ReleasePubKey[63] != 0xa0 {
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
	f := `guild_pubkey = ` + guildPubHex64 + `
release_pubkey = ` + releasePubHex64 + `
release_diviner = file:///tmp/leaked.pem
release_parent_cert = ` + parentCertHex64 + `
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
	f := `release_diviner = badscheme://whatever
`
	c, _ := Parse(strings.NewReader(f))
	if err := validateDivinerScheme(c.ReleaseDiviner); err == nil {
		t.Error("validateDivinerScheme accepted badscheme://")
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
	if err == nil || !strings.Contains(err.Error(), "want 64") {
		t.Errorf("expected length error, got %v", err)
	}
}

func TestParseIgnoresCommentsAndBlankLines(t *testing.T) {
	f := `

# top comment
guild_pubkey = ` + guildPubHex64 + `

    # indented comment
release_pubkey = ` + releasePubHex64 + `

`
	c, err := Parse(strings.NewReader(f))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.GuildPubKey == ([64]byte{}) || c.ReleasePubKey == ([64]byte{}) {
		t.Error("keys not decoded")
	}
}

func TestValidateForBuildDetailedErrors(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"missing guild pubkey", `release_pubkey = ` + releasePubHex64 + `
release_diviner = gcpkms://x
release_parent_cert = ` + parentCertHex64,
			"guild_pubkey"},
		{"missing release signer", `guild_pubkey = ` + guildPubHex64 + `
release_pubkey = ` + releasePubHex64 + `
release_parent_cert = ` + parentCertHex64,
			"release_diviner"},
		{"missing release parent cert", `guild_pubkey = ` + guildPubHex64 + `
release_pubkey = ` + releasePubHex64 + `
release_diviner = gcpkms://ok`,
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
