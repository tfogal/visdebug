#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include "badsync.h"

static float* v3darr;
static size_t dims[3] = {10, 20, 30};

#define IDX3(x,y,z) v[(z)*dims[0]*dims[1] + (y)*dims[0] + x]
__attribute__((noinline)) static void smooth3(float* v) {
  for(size_t k=1; k < dims[2]-1; ++k) {
    for(size_t j=1; j < dims[1]-1; ++j) {
      for(size_t i=1; i < dims[0]-1; ++i) {
        /* hack, doesn't do what it says but still 3D at least.. */
        IDX3(i,j,k) = (IDX3(i-1,j,k) + IDX3(i,j,k) + IDX3(i+1,j,k)) / 3.0f;
      }
    }
  }
}

static void
handle_signal(int sig) {
  signal(sig, SIG_DFL);
  psignal(sig, "sig received.");
}

int main(int argc, char* argv[]) {
  if(argc < 2) {
    fprintf(stderr, "need arg: which computation to run.\n");
    return EXIT_FAILURE;
  }
  signal(SIGUSR1, handle_signal);
  badsync();
#if 0
  printf("[ c] Synchronized.  Now another synchronization...\n");
  badsync();
  printf("[ c] Second synchro complete.  Running program...\n");
#else
  printf("[ c] Synchronized. Moving on...\n");
#endif
  void* justtest;
  if(argc == 42) { dims[0] = 12398; }
  for(size_t i=1; i < (size_t)argc; ++i) {
    if(atoi(argv[i]) == 3) {
      v3darr = calloc(dims[0]*dims[1]*dims[2], sizeof(float));
      printf("[ c] back from calloc.\n");
      smooth3(v3darr);
      free(v3darr);
      printf("[ c] will malloc 42\n");
      justtest = malloc(42);
      printf("[ c] back from malloc.\n");
    } else {
      fprintf(stderr, "[ c] unknown computational id '%s'\n", argv[i]);
      return EXIT_FAILURE;
    }
  }
  free(justtest);
  printf("[ c] %s finished.\n", argv[0]);

  return EXIT_SUCCESS;
}
