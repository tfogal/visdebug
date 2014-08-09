#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

static float vscalar = 0.0f;
static float* varr;
static float* v2darr;
static float* v3darr;
static size_t dims[3] = {10, 20, 30};

static void scalarvar() { vscalar = 42.0f; }
__attribute__((noinline)) static void smooth1() {
  for(size_t i=1; i < dims[0]-1; ++i) {
    varr[i] = (varr[i-1] + varr[i] + varr[i+1]) / 3.0f;
  }
  varr[0] = (varr[0] + varr[1]) / 2.0f;
  const size_t n = dims[0]-1;
  varr[n] = (varr[n-1] + varr[n]) / 2.0f;
}

#define IDX2(x,y) v[(y)*dims[0]+(x)]
__attribute__((noinline)) static void smooth2(float* v) {
  /* top */
  for(size_t x=1; x < dims[0]-1; ++x) {
    IDX2(x,0) = (IDX2(x-1,0) + IDX2(x,0) + IDX2(x+1,0) +
                 IDX2(x-1,1) + IDX2(x,1) + IDX2(x+1,1)) / 6.0f;
  }
  for(size_t y=1; y < dims[1]-1; ++y) {
    for(size_t x=1; x < dims[0]-1; ++x) {
      IDX2(x,y) = (IDX2(x-1,y-1) + IDX2(x,y-1) + IDX2(x+1,y-1) +
                   IDX2(x-1,y)   + IDX2(x,y)   + IDX2(x+1,y) +
                   IDX2(x-1,y+1) + IDX2(x,y+1) + IDX2(x+1,y+1)) / 9.0f;
    }
  }
  /* blah for correctness we need to do sides and bottom too, but blah. */
}
static size_t clamp(int64_t v, size_t max) {
  if(v < 0) {
    return 0;
  }
  if(v >= (int64_t)max) {
    return max-1;
  }
  return v;
}
/*
  const size_t x0 = x < 0 ? 0 : (size_t)x >= dims[0] ? dims[0]-1 : (size_t)x;
  const size_t y0 = y < 0 ? 0 : (size_t)y >= dims[1] ? dims[1]-1 : (size_t)y;
  const size_t z0 = z < 0 ? 0 : (size_t)z >= dims[2] ? dims[2]-1 : (size_t)z;
*/

#define IDX3(x,y,z) ({ \
  const size_t x0 = clamp(x, dims[0]); \
  const size_t y0 = clamp(y, dims[1]); \
  const size_t z0 = clamp(z, dims[2]); \
  v[(z0)*dims[0]*dims[1] + (y0)*dims[0] + x0]; \
})

__attribute__((noinline)) static void smooth3(float* v) {
  for(int64_t k=0; (size_t)k < dims[2]; ++k) {
    for(int64_t j=0; (size_t)j < dims[1]; ++j) {
      for(int64_t i=0; (size_t)i < dims[0]; ++i) {
        const size_t idx = (size_t)k*dims[0]*dims[1] + (size_t)j*dims[0] + i;
        /* technically 1D, but whatever... */
        v[idx] = (IDX3(i-1,j,k) + IDX3(i,j,k) + IDX3(i+1,j,k)) / 3.0f;
      }
    }
  }
}

int main(int argc, char* argv[]) {
  if(argc < 2) {
    fprintf(stderr, "need arg: which computation to run.\n");
    return EXIT_FAILURE;
  }
  if(argc == 42) { dims[0] = 12398; }
  for(size_t i=1; i < (size_t)argc; ++i) {
    if(atoi(argv[i]) == 0) {
      scalarvar();
    } else if(atoi(argv[i]) == 1) {
      varr = calloc(dims[0], sizeof(float));
      smooth1();
      free(varr);
    } else if(atoi(argv[i]) == 2) {
      v2darr = calloc(dims[0]*dims[1], sizeof(float));
      smooth2(v2darr);
      free(v2darr);
    } else if(atoi(argv[i]) == 3) {
      v3darr = calloc(dims[0]*dims[1]*dims[2], sizeof(float));
      smooth3(v3darr);
      free(v3darr);
    } else {
      fprintf(stderr, "unknown computational id '%s'\n", argv[i]);
      return EXIT_FAILURE;
    }
  }
  printf("%s finished.\n", argv[0]);

  return 0;
}
