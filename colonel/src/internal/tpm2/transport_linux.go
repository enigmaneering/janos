// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package tpm2

import (
	"errors"
	"syscall"
)

// linuxRoutes are the standard TPM 2.0 character devices, resource
// manager first (it handles context management and multiplexing).
var linuxRoutes = []string{"/dev/tpmrm0", "/dev/tpm0"}

// devTransport carries commands over a TPM character device using raw
// blocking syscalls.
//
// We deliberately avoid os.File here: os.File registers pollable fds
// with the runtime network poller and drives them non-blocking, and
// the kernel TPM character device does not behave under epoll the way
// a socket does — a non-blocking read after the command write returns
// EOF instead of the response.  Raw blocking read/write on the fd
// (what the kernel's synchronous command/response model actually
// wants) reads the response correctly, matching a plain read(2).
type devTransport struct {
	fd int
}

func openTransport() (transport, error) {
	for _, route := range linuxRoutes {
		fd, err := syscall.Open(route, syscall.O_RDWR, 0)
		if err != nil {
			continue
		}
		return &devTransport{fd: fd}, nil
	}
	return nil, ErrNoDevice
}

func (t *devTransport) submit(cmd []byte) ([]byte, error) {
	// The TPM driver expects a full command in a single write.
	n, err := syscall.Write(t.fd, cmd)
	if err != nil {
		return nil, err
	}
	if n != len(cmd) {
		return nil, errors.New("tpm2: short write to device")
	}
	// A single read returns the whole response; 4 KiB covers every
	// command this package issues.
	buf := make([]byte, 4096)
	n, err = syscall.Read(t.fd, buf)
	if err != nil {
		return nil, err
	}
	if n < 10 {
		return nil, errors.New("tpm2: truncated response from device")
	}
	return buf[:n], nil
}

func (t *devTransport) close() error {
	return syscall.Close(t.fd)
}
