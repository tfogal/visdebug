#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include "badsync.h"

static size_t dims[3] = {10, 20, 30};

__attribute__((pure)) static size_t bound(int val, const size_t mx) {
  if(val < 0) { return 0; }
  if((size_t)val >= mx) { return mx-1; }
  return (size_t)val;
}

static void
batchren() {
  if(system("/home/tfogal/dev/iv3d/BatchRenderer/BatchRenderer -f ./simple.lua") != 0) {
    abort();
  }
}

#define IDX3(x,y,z) \
  ({ \
  const size_t x0 = bound(x, dim[0]); \
  const size_t y0 = bound(y, dim[1]); \
  const size_t z0 = bound(z, dim[2]); \
  data[(z0)*dim[0]*dim[1] + (y0)*dim[0] + x0]; \
  })

__attribute__((noinline)) static void smooth3(const size_t dim[3]) {
  float* data = malloc(dim[0]*dim[1]*dim[2]*sizeof(float));
  for(size_t z=0; z < dim[2]; ++z) {
    for(size_t y=0; y < dim[1]; ++y) {
      for(size_t x=0; x < dim[0]; ++x) {
        data[z*dim[1]*dim[0] + y*dim[0] + x] = drand48()*drand48();
      }
    }
  }

  for(size_t i=0; i < 250; ++i) {
  for(size_t z=0; z < dim[2]; ++z) {
    for(size_t y=0; y < dim[1]; ++y) {
      for(size_t x=0; x < dim[0]; ++x) {
        data[z*dim[1]*dim[0] + y*dim[0]+ x] =
          IDX3(x-1,y-1,z-1)/27.0f + IDX3(x,y-1,z-1)/27.0f + IDX3(x+1,y-1,z-1)/27.0f +
          IDX3(x-1,y+0,z-1)/27.0f + IDX3(x,y+0,z-1)/27.0f + IDX3(x+1,y+0,z-1)/27.0f +
          IDX3(x-1,y+1,z-1)/27.0f + IDX3(x,y+1,z-1)/27.0f + IDX3(x+1,y+1,z-1)/27.0f +

          IDX3(x-1,y-1,z+0)/27.0f + IDX3(x,y-1,z+0)/27.0f + IDX3(x+1,y-1,z+0)/27.0f +
          IDX3(x-1,y+0,z+0)/27.0f + IDX3(x,y+0,z+0)/27.0f + IDX3(x+1,y+0,z+0)/27.0f +
          IDX3(x-1,y+1,z+0)/27.0f + IDX3(x,y+1,z+0)/27.0f + IDX3(x+1,y+1,z+0)/27.0f +

          IDX3(x-1,y-1,z+1)/27.0f + IDX3(x,y-1,z+1)/27.0f + IDX3(x+1,y-1,z+1)/27.0f +
          IDX3(x-1,y+0,z+1)/27.0f + IDX3(x,y+0,z+1)/27.0f + IDX3(x+1,y+0,z+1)/27.0f +
          IDX3(x-1,y+1,z+1)/27.0f + IDX3(x,y+1,z+1)/27.0f + IDX3(x+1,y+1,z+1)/27.0f;
      }
    }
  }
#if 1
  char fname[512];
  snprintf(fname, 512, "%05zu.data.raw", i);
  if(1) {
    printf("fn: %s\n", fname);
    FILE* fp = fopen(fname, "wb");
    if(!fp) { continue; }
    if(fwrite(data, sizeof(float), dim[0]*dim[1]*dim[2], fp) !=
       dim[0]*dim[1]*dim[2]) {
      fprintf(stderr, "error writing '%s'\n", fname);
    }
    fsync(fileno(fp));
    if(fclose(fp) != 0) { fprintf(stderr, "error closing %s\n", fname); }
    char fn2[512];
    snprintf(fn2, 512, "%05zu.data.raw.nhdr", i);
    fp = fopen(fn2, "w");
    if(!fp) { continue; }
    fprintf(fp, "NRRD0001\ntype: float\ndimension: 3\nsizes: %zu %zu %zu\n",
            dim[0], dim[1], dim[2]);
    fprintf(fp, "spacings: 1 1 1\nendian: little\nencoding:raw\n");
    fprintf(fp, "data file: %s\n", fname);
    fsync(fileno(fp));
    fclose(fp);
    fp = fopen(".filename", "w");
    if(!fp) { abort(); }
    fprintf(fp, "%s\n", fn2);
    fsync(fileno(fp));
    if(fclose(fp) != 0) { abort(); }
    batchren();
  }
#endif
  }
  free(data);
}

static void
handle_signal(int sig) {
  signal(sig, SIG_DFL);
  psignal(sig, "[ c] sig received.");
}

int main(int argc, char* argv[]) {
  if(argc < 2) {
    fprintf(stderr, "need arg: which computation to run.\n");
    return EXIT_FAILURE;
  }
  for(size_t i=0; i < (size_t)argc; i++) {
    printf("arg[%zu]: %s\n", i, argv[i]);
  }
  signal(SIGUSR1, handle_signal);
  badsync();
  printf("[ c] Synchronized. Moving on...\n");
  if(argc == 42) { dims[0] = 12398; }
  for(size_t i=1; i < (size_t)argc; ++i) {
    if(atoi(argv[i]) == 3) {
      smooth3(dims);
    }
  }

  printf("[ c] %s finished.\n", argv[0]);
  return EXIT_SUCCESS;
}
