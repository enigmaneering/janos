// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package tpm2

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modTBS                 = syscall.NewLazyDLL("tbs.dll")
	procTbsiContextCreate  = modTBS.NewProc("Tbsi_Context_Create")
	procTbsipContextClose  = modTBS.NewProc("Tbsip_Context_Close")
	procTbsipSubmitCommand = modTBS.NewProc("Tbsip_Submit_Command")
)

// tbsContextParams2 is TBS_CONTEXT_PARAMS2 from tbs.h.  version=2 and
// the includeTpm20 flag (bit 2) request a TPM 2.0 context.
type tbsContextParams2 struct {
	version uint32
	flags   uint32
}

const (
	tbsContextVersionTwo = 2
	tbsIncludeTpm20      = 0x4 // requestRaw:1 includeTpm12:1 includeTpm20:1
	tbsCommandLocality0  = 0
	tbsPriorityNormal    = 200
)

// tbsTransport carries commands through TPM Base Services.
type tbsTransport struct {
	ctx uintptr
}

func openTransport() (transport, error) {
	if err := procTbsiContextCreate.Find(); err != nil {
		return nil, ErrNoDevice
	}
	params := tbsContextParams2{version: tbsContextVersionTwo, flags: tbsIncludeTpm20}
	var ctx uintptr
	r, _, _ := procTbsiContextCreate.Call(
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if r != 0 {
		return nil, ErrNoDevice
	}
	return &tbsTransport{ctx: ctx}, nil
}

func (t *tbsTransport) submit(cmd []byte) ([]byte, error) {
	resp := make([]byte, 4096)
	respLen := uint32(len(resp))
	r, _, _ := procTbsipSubmitCommand.Call(
		t.ctx,
		uintptr(tbsCommandLocality0),
		uintptr(tbsPriorityNormal),
		uintptr(unsafe.Pointer(&cmd[0])),
		uintptr(len(cmd)),
		uintptr(unsafe.Pointer(&resp[0])),
		uintptr(unsafe.Pointer(&respLen)),
	)
	if r != 0 {
		return nil, fmt.Errorf("tpm2: Tbsip_Submit_Command failed, TBS_RESULT 0x%08X", uint32(r))
	}
	if respLen < 10 {
		return nil, errors.New("tpm2: truncated response from TBS")
	}
	return resp[:respLen], nil
}

func (t *tbsTransport) close() error {
	if t.ctx == 0 {
		return nil
	}
	procTbsipContextClose.Call(t.ctx)
	t.ctx = 0
	return nil
}
