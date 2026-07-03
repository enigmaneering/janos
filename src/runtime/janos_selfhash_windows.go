// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

// JanOS: binary self-attestation, Windows reader.
//
// Windows exposes the running executable via the PE loader.  We call
// GetModuleFileNameW(NULL, ...) to get the exe's on-disk path as a
// UTF-16 string, then CreateFileW + ReadFile to stream the bytes
// through SHA-256.  The runtime's unix-shaped open/read/closefd stubs
// on Windows just throw, so we go direct to kernel32 via the standard
// runtime stdcall / cgo_import_dynamic pattern.

package runtime

import "unsafe"

//go:cgo_import_dynamic runtime._GetModuleFileNameW GetModuleFileNameW%3 "kernel32.dll"
//go:cgo_import_dynamic runtime._CreateFileW CreateFileW%7 "kernel32.dll"
//go:cgo_import_dynamic runtime._ReadFile ReadFile%5 "kernel32.dll"

var (
	_GetModuleFileNameW,
	_CreateFileW,
	_ReadFile stdFunction
)

const (
	janosWinMaxPath             = 1024
	janosWinGenericRead         = 0x80000000
	janosWinFileShareRead       = 0x00000001
	janosWinOpenExisting        = 3
	janosWinFileAttributeNormal = 0x80
	janosWinReadChunk           = 4096
)

var janosWinInvalidHandleValue = ^uintptr(0)

func janosInitBinaryHash() {
	var path [janosWinMaxPath + 1]uint16
	n := stdcall(_GetModuleFileNameW, 0, uintptr(unsafe.Pointer(&path[0])), uintptr(janosWinMaxPath))
	if n == 0 || n >= janosWinMaxPath {
		return
	}
	path[n] = 0

	handle := stdcall(_CreateFileW,
		uintptr(unsafe.Pointer(&path[0])),
		janosWinGenericRead,
		janosWinFileShareRead,
		0,
		janosWinOpenExisting,
		janosWinFileAttributeNormal,
		0)
	if handle == janosWinInvalidHandleValue {
		return
	}

	var d janosSHA256
	d.Reset()
	var buf [janosWinReadChunk]byte
	for {
		var got uint32
		ok := stdcall(_ReadFile,
			handle,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&got)),
			0)
		if ok == 0 {
			stdcall(_CloseHandle, handle)
			return
		}
		if got == 0 {
			break
		}
		d.Write(buf[:got])
	}
	stdcall(_CloseHandle, handle)
	janosStoreBinaryHash(d.Sum())
}
