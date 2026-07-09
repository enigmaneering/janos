// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tpm2 is a minimal TPM 2.0 command layer for JanOS.
//
// It speaks the TCG TPM 2.0 wire format directly — command and
// response byte streams — over whatever transport the host provides:
// a character device on Linux (/dev/tpmrm0), TPM Base Services on
// Windows.  The marshalling is identical across platforms; only the
// transport differs.  No cgo, no external module dependency.
//
// This first cut covers the operations JanOS needs to characterize a
// TPM and prove the transport works end to end: GetRandom (the RNG,
// the simplest possible round-trip) and GetCapability (manufacturer,
// family, firmware).  The key-hierarchy operations that back
// hardware-wrapped identities — CreatePrimary, Create, Load, ECDH,
// Sign — build on the same transact core and land in a later pass.
//
// It is deliberately internal: the public, role-neutral surface is
// package attest, which uses this layer for the TPM mechanism and a
// different one for the Secure Enclave.
package tpm2

import (
	"errors"
	"fmt"
)

// ErrNoDevice is returned by Open when no TPM transport is available
// on this platform (no device node, no TBS, or an unsupported GOOS).
var ErrNoDevice = errors.New("tpm2: no TPM device available")

// TPM 2.0 structure tags.
const (
	tagNoSessions uint16 = 0x8001 // TPM_ST_NO_SESSIONS
)

// Command codes (TPM_CC).
const (
	ccGetCapability uint32 = 0x0000017A
	ccGetRandom     uint32 = 0x0000017B
)

// Capability selectors (TPM_CAP).
const (
	capTPMProperties uint32 = 0x00000006 // TPM_CAP_TPM_PROPERTIES
)

// Fixed property tags (TPM_PT), all in the "fixed" group at 0x100.
const (
	ptFamilyIndicator   uint32 = 0x00000100 // "2.0\0"
	ptRevision          uint32 = 0x00000102 // spec revision ×100
	ptManufacturer      uint32 = 0x00000105 // 4 ASCII bytes
	ptVendorString1     uint32 = 0x00000106 // 4 ASCII bytes each
	ptVendorString4     uint32 = 0x00000109
	ptFirmwareVersion1  uint32 = 0x0000010B
	ptFirmwareVersion2  uint32 = 0x0000010C
	ptFixedPropretyBase uint32 = 0x00000100
)

// transport is the platform-specific byte-stream carrier.  A command
// buffer goes in, a response buffer comes back.  Implementations live
// in transport_<goos>.go.
type transport interface {
	submit(cmd []byte) (resp []byte, err error)
	close() error
}

// Device is an open connection to a TPM 2.0.
type Device struct {
	t transport
}

// Open connects to the platform TPM.  Returns ErrNoDevice if none is
// present or reachable.
func Open() (*Device, error) {
	t, err := openTransport()
	if err != nil {
		return nil, err
	}
	return &Device{t: t}, nil
}

// Close releases the transport.
func (d *Device) Close() error {
	if d.t == nil {
		return nil
	}
	return d.t.close()
}

// -- wire helpers -----------------------------------------------------
//
// TPM 2.0 is big-endian throughout.  These hand-rolled packers keep
// the package free of an encoding/binary dependency.

func putU16(b []byte, v uint16) { b[0] = byte(v >> 8); b[1] = byte(v) }
func putU32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}
func u16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
func u32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// buildCommand frames a command: header (tag, size, code) followed by
// the already-marshalled parameter bytes.
func buildCommand(tag uint16, code uint32, params []byte) []byte {
	cmd := make([]byte, 10+len(params))
	putU16(cmd[0:2], tag)
	putU32(cmd[2:6], uint32(len(cmd)))
	putU32(cmd[6:10], code)
	copy(cmd[10:], params)
	return cmd
}

// parseResponseHeader validates the 10-byte response header and
// returns the parameter area (everything after it).  A non-zero
// responseCode becomes an error.
func parseResponseHeader(resp []byte) (params []byte, err error) {
	if len(resp) < 10 {
		return nil, fmt.Errorf("tpm2: short response (%d bytes)", len(resp))
	}
	size := u32(resp[2:6])
	if int(size) != len(resp) {
		return nil, fmt.Errorf("tpm2: response size field %d != actual %d", size, len(resp))
	}
	if rc := u32(resp[6:10]); rc != 0 {
		return nil, fmt.Errorf("tpm2: command failed, responseCode 0x%08X", rc)
	}
	return resp[10:], nil
}

// transact submits a framed command and returns its parameter area.
func (d *Device) transact(tag uint16, code uint32, params []byte) ([]byte, error) {
	cmd := buildCommand(tag, code, params)
	resp, err := d.t.submit(cmd)
	if err != nil {
		return nil, err
	}
	return parseResponseHeader(resp)
}

// -- GetRandom --------------------------------------------------------

// GetRandom returns n bytes from the TPM's hardware RNG.  n is capped
// per call by the TPM (typically the digest size); callers needing
// more should loop.
func (d *Device) GetRandom(n int) ([]byte, error) {
	if n <= 0 || n > 0xFFFF {
		return nil, fmt.Errorf("tpm2: GetRandom count %d out of range", n)
	}
	var params [2]byte
	putU16(params[:], uint16(n))
	out, err := d.transact(tagNoSessions, ccGetRandom, params[:])
	if err != nil {
		return nil, err
	}
	// Response parameter area: TPM2B_DIGEST = size(2) || bytes.
	if len(out) < 2 {
		return nil, errors.New("tpm2: GetRandom response too short")
	}
	sz := int(u16(out[0:2]))
	if 2+sz > len(out) {
		return nil, fmt.Errorf("tpm2: GetRandom claims %d bytes, have %d", sz, len(out)-2)
	}
	return out[2 : 2+sz], nil
}

// -- GetCapability (fixed properties) ---------------------------------

// Info describes a TPM's fixed identity properties.
type Info struct {
	Manufacturer    string // 4-char vendor ID, e.g. "IBM", "STM", "PRLS"
	VendorString    string // concatenated vendor strings 1..4
	Family          string // "2.0"
	FirmwareVersion uint64 // (firmware1 << 32) | firmware2
	SpecRevision    uint32 // spec revision ×100 (e.g. 164 => 1.64)
}

// Info reads the fixed-property group and assembles a TPM identity.
func (d *Device) Info() (Info, error) {
	props, err := d.getProperties(ptFixedPropretyBase, 32)
	if err != nil {
		return Info{}, err
	}
	var info Info
	var fw1, fw2 uint32
	var vs [4]uint32
	for tag, val := range props {
		switch tag {
		case ptFamilyIndicator:
			info.Family = trimASCII(val)
		case ptRevision:
			info.SpecRevision = val
		case ptManufacturer:
			info.Manufacturer = trimASCII(val)
		case ptVendorString1:
			vs[0] = val
		case ptVendorString1 + 1:
			vs[1] = val
		case ptVendorString1 + 2:
			vs[2] = val
		case ptVendorString4:
			vs[3] = val
		case ptFirmwareVersion1:
			fw1 = val
		case ptFirmwareVersion2:
			fw2 = val
		}
	}
	info.FirmwareVersion = uint64(fw1)<<32 | uint64(fw2)
	for _, v := range vs {
		if v != 0 {
			info.VendorString += trimASCII(v)
		}
	}
	return info, nil
}

// getProperties issues GetCapability(TPM_CAP_TPM_PROPERTIES, base,
// count) and returns the tag->value map from the response.
func (d *Device) getProperties(base uint32, count uint32) (map[uint32]uint32, error) {
	var params [12]byte
	putU32(params[0:4], capTPMProperties)
	putU32(params[4:8], base)
	putU32(params[8:12], count)
	out, err := d.transact(tagNoSessions, ccGetCapability, params[:])
	if err != nil {
		return nil, err
	}
	// Response parameter area:
	//   moreData (1) || capability (4) || propertyCount (4) ||
	//   propertyCount × { property (4) || value (4) }
	if len(out) < 9 {
		return nil, errors.New("tpm2: GetCapability response too short")
	}
	cap := u32(out[1:5])
	if cap != capTPMProperties {
		return nil, fmt.Errorf("tpm2: GetCapability echoed capability 0x%08X", cap)
	}
	pc := u32(out[5:9])
	body := out[9:]
	if len(body) < int(pc)*8 {
		return nil, fmt.Errorf("tpm2: GetCapability claims %d properties, body has %d bytes", pc, len(body))
	}
	props := make(map[uint32]uint32, pc)
	for i := uint32(0); i < pc; i++ {
		off := int(i) * 8
		props[u32(body[off:off+4])] = u32(body[off+4 : off+8])
	}
	return props, nil
}

// trimASCII renders a big-endian uint32 as up to 4 printable ASCII
// characters, dropping NULs and non-printables (TPM vendor IDs are
// space- or NUL-padded).
func trimASCII(v uint32) string {
	b := []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	out := make([]byte, 0, 4)
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		}
	}
	return string(out)
}
