/* Simple program to allocate and then access memory.  Used to stress our
 * access vs. allocate overheads */
#include <stdio.h>
#include <stdlib.h>

void f(int* arr) {
  *arr = 42;
}

int main(int argc, char *argv[]) {
  if(argc != 2) {
    fprintf(stderr, "need # of iterations!\n");
    return EXIT_FAILURE;
  }
  const size_t n = atoi(argv[1]);
  void* p;
  for(size_t i=0; i < n; ++i) {
    p = malloc(i*42);
    f((int*)p);
    free(p);
  }
  return EXIT_SUCCESS;
}
