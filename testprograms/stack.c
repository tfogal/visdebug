#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include "badsync.h"

static void
handle_signal(int sig) {
  signal(sig, SIG_DFL);
  psignal(sig, "sig received.");
}

#define whereami(prefix, ...) \
  do { \
    uint64_t rsp=0; asm("\t movq %%rsp, %0" : "=r"(rsp)); \
    uint64_t rip=0; asm("\t movq $., %0" : "=r"(rip)); \
    printf("[ c] 0x%08lx 0x%08lx ", rsp, rip); \
    printf(prefix, __VA_ARGS__); \
    printf("\n"); fflush(stdout); \
  } while(0)

int x;
int y;
int z;

void setz() { z = 42; }
void sety() { y = 19; setz(); }
void setx() { x = 12; sety(); }
void myfunc() { setx(); }
    
int main(int argc, char* argv[]) {
  if(argc < 2) {
    fprintf(stderr, "need sz arg\n");
    return EXIT_FAILURE;
  }
  for(size_t i=0; i < (size_t)argc; i++) {
    printf("arg[%zu]: %s\n", i, argv[i]);
  }
  printf("[ c] my PID is %ld\n", (long)getpid());
  signal(SIGUSR1, handle_signal);
  badsync();
  printf("[ c] Synchronized. Moving on...\n");

  if(atoi(argv[1]) == 19) { // don't let compiler optimize x,y,z out.
    printf("x,y,z: %d %d %d\n", x,y,z);
  }
  printf("addresses: myfunc, setx, sety, setz: %p %p %p %p\n", myfunc, setx,
         sety, setz);
  myfunc();

  void* p = malloc(x);
  printf("p: %p\n", p);
  free(p);
  p = calloc(12, 54);
  free(p);

  return EXIT_SUCCESS;
}
