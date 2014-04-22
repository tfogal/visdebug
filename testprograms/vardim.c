#include <stdlib.h>
#include <stdio.h>

static float vscalar = 0.0f;
static float* varr;
static float* v2darr;
static float* v3darr;
static size_t dims[3] = {10, 20, 30};

static void scalarvar() { vscalar = 42.0f; }
#if 0
static void smooth1(float* v) {
  for(size_t i=1; i < dims[0]-1; ++i) {
    v[i] = (v[i-1] + v[i] + v[i+1]) / 3.0f;
  }
  v[0] = (v[0] + v[1]) / 2.0f;
  const size_t n = dims[0]-1;
  v[n] = (v[n-1] + v[n]) / 2.0f;
}
#else
__attribute__((noinline)) static void smooth1() {
  for(size_t i=1; i < dims[0]-1; ++i) {
    varr[i] = (varr[i-1] + varr[i] + varr[i+1]) / 3.0f;
  }
  varr[0] = (varr[0] + varr[1]) / 2.0f;
  const size_t n = dims[0]-1;
  varr[n] = (varr[n-1] + varr[n]) / 2.0f;
}
#endif

#define IDX2(x,y) v[(y)*dims[0]+(x)]
static void smooth2(float* v) {
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

#define IDX3(x,y,z) v[(z)*dims[0]*dims[1] + (y)*dims[0] + x]
static void smooth3(float* v) {
  for(size_t k=1; k < dims[2]-1; ++k) {
    for(size_t j=1; j < dims[1]-1; ++j) {
      for(size_t i=1; i < dims[0]-1; ++i) {
        /* hack, doesn't do what it says but still 3D at least.. */
        IDX3(i,j,k) = (IDX3(i-1,j,k) + IDX3(i,j,k) + IDX3(i+1,j,k)) / 3.0f;
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
      /*smooth1(varr);*/
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

  return 0;
}
