/* Distributed under the MIT license.  See the LICENSE file.
 * Copyright (c) 2014--2016 Thomas Fogal */
#include <stdlib.h>
#include <stdio.h>

static void conditional(int v) {
  if(v < 42) {
    printf("less than 42\n");
  } else {
    printf("geq 42\n");
  }
}
static void conditional_simple(int v) {
  if(v < 42) {
    printf("less than 42\n");
    return;
  }
  printf("geq 42\n");
}
static void switchstmt(const int v) {
  switch(v) {
    case 0: printf("0\n"); break;
    case 1: /* fall-through */
    case 2: printf("1 or 2\n"); break;
    case 3:
    case 4:
    case 5: printf("3, 4, or 5\n"); break;
    default: printf("other\n"); break;
  }
}
static void switchloop(const int v, size_t n) {
  int x = 19;
  for(size_t i=0; i < n; ++i) {
    switch(v) {
      case 0: printf("0\n"); break;
      case 1: /* fall-through */
      case 2:
        if(n < 12) {
          x = 42;
        } else {
          x = 14;
        }
        break;
      case 3:
      case 4:
      case 5: printf("3, 4, or 5\n"); break;
      default: printf("other\n"); break;
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
  conditional(arg);
  conditional_simple(arg);
  switchstmt(arg);
  switchloop(arg, (size_t)atoi(argv[2]));

  return 0;
}
