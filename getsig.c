#define _POSIX_C_SOURCE 201212L
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

// Go doesn't provide a way to get signals, so we manually implement it.
// This is basically ptrace(PTRACE_GETSIGINFO, ...)
siginfo_t getsig(pid_t pid) {
  siginfo_t rv;
  memset(&rv, 0, sizeof(siginfo_t));
  if(ptrace(PTRACE_SETSIGINFO, pid, NULL, &rv) != 0) {
    const int err = errno;
    fprintf(stderr, "error grabbing signal: %d\n", err);
    return rv; // no multiple return values, and ptrs suck in Cgo...
  }
  return rv;
}

// Despite documentation, si_trapno is not actually a valid field.
int sig_trapno(siginfo_t si) { (void)si; assert(0); return 0; }
void* sig_addr(siginfo_t si) { return si.si_addr; }
