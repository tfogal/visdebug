#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "tiny.h"

int main() {
  extfunc(42);
  pause();
  void* v = malloc(42);
  printf("vaddr: %p\n", v);
  free(v);
  return 0;
}
