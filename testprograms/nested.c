#include <stdlib.h>
#include <stdio.h>

static void nestedloop(const int v, size_t n) {
  if(v > 36) {
    puts("hi");
  }
  if(v > 20) {
    printf("x: %d\n", v);
  } else {
    printf("x: %d\n", v+12);
  }
}

int main(int argc, char* argv[]) {
  if(argc < 3) {
    fprintf(stderr, "need arg: integer, num\n");
    return EXIT_FAILURE;
  }
  int arg = atoi(argv[1]);
  nestedloop(arg, (size_t)atoi(argv[2]));

  return 0;
}
