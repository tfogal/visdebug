package main

// #cgo CFLAGS: -std=c99
// #include "getsig.h"
import "C"

type siginfo struct {
  Signo int       // signal number
  Errno int       // An errno value
  Code int        // signal code
  Trapno int      // trap number that caused hardware-generated signal
  pid int64       // Sending process ID
  uid int64       // Real user ID of sending process
  status int      // Exit value or signal
  utime uint64    // User time consumed
  stime uint64    // System time consumed
  // 'Signal value' ignored because I don't know how to represent it.
  // 'POSIX.1b signal' ignored because i don't know what it's for.
  // 'POSIX.1b signal' ignored because i don't know what it's for.
  overrun int     // Timer overrun count; POSIX.1b timers
  timerid int     // Timer ID; POSIX.1b timers
  Addr uintptr    // Memory location which caused fault
  band int64      // Band event (was int in glibc 2.3.2 and earlier)
  fd int          // File descriptor
  addr_lsb int16  // Least significant bit of address (since Linux 2.6.32)
}

func get_siginfo(pid int) (siginfo, error) {
  si, errno := C.getsig(C.pid_t(pid))
  if errno != nil {
    return siginfo{}, errno
  }
  siginf := siginfo{
    Signo: int(si.si_signo),
    Errno: int(si.si_errno),
    Code: int(si.si_code),
    Trapno: int(C.sig_trapno(si)),
    Addr: uintptr(C.sig_addr(si)),
  }
  return siginf, nil
}
