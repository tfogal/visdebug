#include <stdlib.h>
#include <stdio.h>

static void contloop(const int v, size_t n) {
  int x = 19;
  for(size_t i=0; i < n; ++i) {
    if(v < 42) {
      x = 12;
    } else {
      continue;
    }
  }
  printf("x: %d\n", x);
}

static void contnoelse(const int v, size_t n) {
  int x = 19;
  for(size_t i=0; i < n; ++i) {
    if(v < 42) {
      x = 12;
    }
    continue;
  }
  printf("x: %d\n", x);
}
static void contloop2d(const int v, size_t n) {
  int x = 19;
  for(size_t i=0; i < n; ++i) {
    for(size_t j=0; j < n; ++j) {
      if(v < 42) {
        x = 12;
      } else {
        continue;
      }
    }
  }
  printf("x: %d\n", x);
}



int main(int argc, char* argv[]) {
  if(argc < 3) {
    fprintf(stderr, "need arg: integer, num\n");
    return EXIT_FAILURE;
  }
  int arg = atoi(argv[1]);
  contloop(arg, (size_t)atoi(argv[2]));
  contnoelse(arg, (size_t)atoi(argv[2]));
  contloop2d(arg, (size_t)atoi(argv[2]));

  return 0;
}
