/* Distributed under the MIT license.  See the LICENSE file.
 * Copyright (c) 2014--2016 Thomas Fogal */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  if(argc != 2) {
    fprintf(stderr, "need # of iterations!\n");
    return EXIT_FAILURE;
  }
  const size_t n = atoi(argv[1]);
  void* p;
  for(size_t i=0; i < n; ++i) {
    p = malloc(i*42);
    free(p);
  }
  return EXIT_SUCCESS;
}
