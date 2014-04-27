#include <stdlib.h>
#include <stdio.h>

static void iffollowingif(const int v) {
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
  if(argc < 2) {
    fprintf(stderr, "need arg: integer\n");
    return EXIT_FAILURE;
  }
  int arg = atoi(argv[1]);
  iffollowingif(arg);

  return 0;
}
