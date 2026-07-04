//go:build windows

// JanOS: binary self-attestation, Windows reader.
//
// Windows exposes the running executable via the PE loader.  We call
// GetModuleFileNameW(NULL, ...) to get the exe's on-disk path as a
// UTF-16 string, then CreateFileW to open it and ReadFile to fill a
// VirtualAlloc'd buffer.  Once the whole binary is in memory we hand
// it to the same portable janosHashCanonical the unix path uses.
//
// VirtualAlloc plays the same role as the unix mmap(MAP_ANON): it
// bypasses the Go allocator, so TestMemPprof does not see the multi-
// MB mapping in its alloc profile.  _VirtualAlloc / _VirtualFree /
// _CloseHandle are already imported by os_windows.go — reuse those.

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
	janosWinReadChunk           = 1 << 20 // 1 MiB per ReadFile call
	janosWinMemCommitReserve    = _MEM_COMMIT | _MEM_RESERVE
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
	defer stdcall(_CloseHandle, handle)

	buf, mapped := janosWinVirtualAlloc(janosMaxBinarySize)
	if buf == nil {
		return
	}
	defer janosWinVirtualFree(buf, mapped)

	total := 0
	for total < mapped {
		var got uint32
		want := mapped - total
		if want > janosWinReadChunk {
			want = janosWinReadChunk
		}
		ok := stdcall(_ReadFile,
			handle,
			uintptr(unsafe.Pointer(&buf[total])),
			uintptr(want),
			uintptr(unsafe.Pointer(&got)),
			0)
		if ok == 0 {
			return
		}
		if got == 0 {
			break
		}
		total += int(got)
	}
	if total == 0 || total >= mapped {
		return
	}

	janosStoreBinaryHash(janosHashCanonical(buf[:total]))
}

// janosWinVirtualAlloc reserves+commits an anonymous VA region via
// VirtualAlloc, mirroring the unix janosMmapAnon.  The returned []byte
// is a view over the raw pages; it does NOT participate in Go's GC.
// Free with janosWinVirtualFree.
func janosWinVirtualAlloc(size int) ([]byte, int) {
	if size <= 0 {
		return nil, 0
	}
	p := stdcall(_VirtualAlloc, 0, uintptr(size), janosWinMemCommitReserve, _PAGE_READWRITE)
	if p == 0 {
		return nil, 0
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(p)), size), size
}

// janosWinVirtualFree releases a region obtained via janosWinVirtualAlloc.
// MEM_RELEASE with size=0 is the Windows contract for the reservation
// as a whole.
func janosWinVirtualFree(buf []byte, size int) {
	if len(buf) == 0 || size <= 0 {
		return
	}
	stdcall(_VirtualFree, uintptr(unsafe.Pointer(&buf[0])), 0, _MEM_RELEASE)
}
