// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

<<<<<<< HEAD:vendor/golang.org/x/sys/unix/asm_bsd_386.s
//go:build (freebsd || netbsd || openbsd) && gc
// +build freebsd netbsd openbsd
=======
//go:build (darwin || freebsd || netbsd || openbsd) && gc
// +build darwin freebsd netbsd openbsd
>>>>>>> 0c14db0fb (WIP spire.):vendor/golang.org/x/sys/unix/asm_darwin_386.s
// +build gc

#include "textflag.h"

// System call support for 386 BSD

// Just jump to package syscall's implementation for all these functions.
// The runtime may know about them.

TEXT	·Syscall(SB),NOSPLIT,$0-28
	JMP	syscall·Syscall(SB)

TEXT	·Syscall6(SB),NOSPLIT,$0-40
	JMP	syscall·Syscall6(SB)

TEXT	·Syscall9(SB),NOSPLIT,$0-52
	JMP	syscall·Syscall9(SB)

TEXT	·RawSyscall(SB),NOSPLIT,$0-28
	JMP	syscall·RawSyscall(SB)

TEXT	·RawSyscall6(SB),NOSPLIT,$0-40
	JMP	syscall·RawSyscall6(SB)
