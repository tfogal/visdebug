#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

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

#define whereami(prefix, ...) \
  do { \
    uint64_t rsp=0; asm("\t movq %%rsp, %0" : "=r"(rsp)); \
    uint64_t rip=0; asm("\t movq $., %0" : "=r"(rip)); \
    printf("[ c] 0x%08lx 0x%08lx ", rsp, rip); \
    printf(prefix, __VA_ARGS__); \
    printf("\n"); fflush(stdout); \
  } while(0)

int main(int argc, char* argv[]) {
  if(argc < 2) {
    fprintf(stderr, "need arg: which computation to run.\n");
    return EXIT_FAILURE;
  }
  for(size_t i=0; i < (size_t)argc; i++) {
    printf("arg[%zu]: %s\n", i, argv[i]);
  }
  printf("[ c] my PID is %ld\n", (long)getpid());
  signal(SIGUSR1, handle_signal);

  pause();

  void* justtest;
  if(argc == 42) { dims[0] = 12398; }
  for(size_t i=1; i < (size_t)argc; ++i) {
    if(atoi(argv[i]) == 3) {
      v3darr = calloc(dims[0]*dims[1]*dims[2], sizeof(float));
      whereami("back from calloc(%zu, %zu)", dims[0]*dims[1]*dims[2],
               sizeof(float));
      smooth3(v3darr);
      free(v3darr);
      whereami("will malloc %s", "42");
      justtest = malloc(42);
      whereami("back from malloc(42), got %p", justtest);
      free(justtest);
    } else {
      fprintf(stderr, "[ c] unknown computational id '%s'\n", argv[i]);
    }
  }
  justtest = malloc(19);
  whereami("malloc(19) came back: %p", justtest);
  free(justtest);
  justtest = malloc(7);
  whereami("malloc(7) gave: %p", justtest);
  free(justtest);
  whereami("%s finished.", argv[0]);

  return EXIT_SUCCESS;
}
