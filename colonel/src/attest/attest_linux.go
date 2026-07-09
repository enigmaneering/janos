// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package attest

import (
	"fmt"
	"internal/tpm2"
	"os"
	"strings"
)

// linuxTPMRoutes are the standard character devices for TPM 2.0
// access, in preference order: the in-kernel resource manager first
// (it multiplexes access and manages transient object contexts), then
// the raw device.
var linuxTPMRoutes = []string{"/dev/tpmrm0", "/dev/tpm0"}

func probe() (Capability, error) {
	for _, route := range linuxTPMRoutes {
		if _, err := os.Stat(route); err != nil {
			continue // not present at this route
		}
		// Present.  Confirm we can actually open it — a JanOS colonel
		// runs privileged, but a development process may lack the
		// tss-group permission, which is a distinct, actionable
		// condition rather than "no TPM".
		f, err := os.OpenFile(route, os.O_RDWR, 0)
		if err != nil {
			return Capability{
					Mechanism: MechanismTPM20,
					Route:     route,
					Version:   linuxTPMVersion(),
				},
				fmt.Errorf("attest: TPM present at %s but not accessible: %w", route, err)
		}
		f.Close()
		c := Capability{
			Mechanism: MechanismTPM20,
			Route:     route,
			Version:   linuxTPMVersion(),
			Vendor:    linuxTPMVendor(),
		}
		enrichFromTPM(&c)
		return c, nil
	}
	return Capability{}, ErrUnavailable
}

// enrichFromTPM opens the TPM directly and replaces the best-effort
// sysfs Vendor/Version with the device's own reported identity —
// manufacturer and firmware straight from TPM2_GetCapability.  Any
// failure leaves the sysfs-derived fields in place; detection never
// depends on the richer query succeeding.
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
	for _, route := range linuxTPMRoutes {
		if _, err := os.Stat(route); err == nil {
			if f, err := os.OpenFile(route, os.O_RDWR, 0); err == nil {
				f.Close()
				return true
			}
		}
	}
	return false
}

// linuxTPMVersion reads the TPM major version the kernel exposes in
// sysfs (present since Linux 5.4).  Returns "" when the file is
// absent (older kernels) — detection does not depend on it.
func linuxTPMVersion() string {
	b, err := os.ReadFile("/sys/class/tpm/tpm0/tpm_version_major")
	if err != nil {
		return ""
	}
	switch strings.TrimSpace(string(b)) {
	case "2":
		return "TPM 2.0"
	case "1":
		return "TPM 1.2"
	}
	return ""
}

// linuxTPMVendor best-effort reads a human-readable device
// description from sysfs.  The exact file varies by kernel and TPM
// driver; we try the common locations and return "" if none exist.
func linuxTPMVendor() string {
	for _, p := range []string{
		"/sys/class/tpm/tpm0/device/description",
		"/sys/class/tpm/tpm0/device/caps",
	} {
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s
			}
		}
	}
	return ""
}
