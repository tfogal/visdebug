#ifndef VISDBG_GETSIG_H
#define VISDBG_GETSIG_H
#define _POSIX_C_SOURCE 201212L

#include <signal.h>
#include <unistd.h>

// Go doesn't provide a way to get signals, so we manually implement it.
// This is basically ptrace(PTRACE_GETSIGINFO, ...)
siginfo_t getsig(pid_t);

// Since many elements of the siginfo_t are not actually fields as
// defined in the manpage/standard (rather, they are unions, etc.), Go
// cannot access them intelligently.  These functions just grab the
// corresponding field.
extern int sig_trapno(siginfo_t);
extern void* sig_addr(siginfo_t);

#endif
