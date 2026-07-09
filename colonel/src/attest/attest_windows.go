// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package attest

import (
	"internal/tpm2"
	"syscall"
	"unsafe"
)

// TPM Base Services (TBS) is the Windows standard route to the TPM.
// Tbsi_GetDeviceInfo reports the device's TPM version without opening
// a command context, which is exactly the cheap presence-and-version
// probe we want.
var (
	modTBS                = syscall.NewLazyDLL("tbs.dll")
	procTbsiGetDeviceInfo = modTBS.NewProc("Tbsi_GetDeviceInfo")
)

// tpmDeviceInfo mirrors TPM_DEVICE_INFO from tbs.h.  tpmVersion is 1
// for TPM 1.2 and 2 for TPM 2.0.
type tpmDeviceInfo struct {
	structVersion    uint32
	tpmVersion       uint32
	tpmInterfaceType uint32
	tpmImpRevision   uint32
}

// tbsDeviceInfo calls Tbsi_GetDeviceInfo, returning the reported
// tpmVersion and whether the call succeeded.  A missing tbs.dll or
// export (older/embedded Windows) is treated as "no TPM" rather than
// an error.
func tbsDeviceInfo() (version uint32, ok bool) {
	if err := procTbsiGetDeviceInfo.Find(); err != nil {
		return 0, false
	}
	var info tpmDeviceInfo
	r, _, _ := procTbsiGetDeviceInfo.Call(
		unsafe.Sizeof(info),
		uintptr(unsafe.Pointer(&info)),
	)
	// TBS_RESULT: 0 is TBS_SUCCESS; anything else (e.g.
	// TBS_E_TPM_NOT_FOUND) means no usable device.
	if r != 0 {
		return 0, false
	}
	return info.tpmVersion, true
}

func probe() (Capability, error) {
	version, ok := tbsDeviceInfo()
	if !ok {
		return Capability{}, ErrUnavailable
	}
	// This first pass targets TPM 2.0.  A reported 1.2 device is real
	// hardware but not a mechanism we drive yet, so it reads as
	// unavailable rather than a MechanismTPM20 we cannot honor.
	if version != 2 {
		return Capability{}, ErrUnavailable
	}
	c := Capability{
		Mechanism: MechanismTPM20,
		Route:     "TBS",
		Version:   "TPM 2.0",
	}
	enrichFromTPM(&c)
	return c, nil
}

// enrichFromTPM opens the TPM through TBS and replaces the generic
// "TPM 2.0" identity with the device's own manufacturer and family
// from TPM2_GetCapability.  Any failure leaves the fields untouched;
// detection does not depend on it.
func enrichFromTPM(c *Capability) {
	dev, err := tpm2.Open()
	if err != nil {
		return
	}
	defer dev.Close()
	info, err := dev.Info()
	if err != nil {
		return
	}
	if info.Manufacturer != "" {
		c.Vendor = info.Manufacturer
	}
	if info.Family != "" {
		c.Version = "TPM " + info.Family
	}
}

func available() bool {
	_, err := probe()
	return err == nil
}
