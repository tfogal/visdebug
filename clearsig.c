#define _POSIX_C_SOURCE 200112L
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

int clearsignal(long pid) {
  siginfo_t si;
  memset(&si, 0, sizeof(siginfo_t));
  if(ptrace(PTRACE_SETSIGINFO, (pid_t)pid, NULL, &si) != 0) {
    const int err = errno;
    fprintf(stderr, "error clearing signals: %d\n", err);
    return err;
  }
  return 0;
}
