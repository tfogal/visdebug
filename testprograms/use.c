/* Distributed under the MIT license.  See the LICENSE file.
 * Copyright (c) 2014--2016 Thomas Fogal */
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
