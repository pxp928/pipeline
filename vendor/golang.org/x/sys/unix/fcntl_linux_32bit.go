// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

<<<<<<< HEAD
//go:build (linux && 386) || (linux && arm) || (linux && mips) || (linux && mipsle) || (linux && ppc)
// +build linux,386 linux,arm linux,mips linux,mipsle linux,ppc
=======
//go:build (linux && 386) || (linux && arm) || (linux && mips) || (linux && mipsle)
// +build linux,386 linux,arm linux,mips linux,mipsle
>>>>>>> 0c14db0fb (WIP spire.)

package unix

func init() {
	// On 32-bit Linux systems, the fcntl syscall that matches Go's
	// Flock_t type is SYS_FCNTL64, not SYS_FCNTL.
	fcntl64Syscall = SYS_FCNTL64
}
