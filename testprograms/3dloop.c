/* Distributed under the MIT license.  See the LICENSE file.
 * Copyright (c) 2014--2016 Thomas Fogal */
#include <stdlib.h>
#include <stdio.h>

void subfunc(unsigned n) {
  const char* hello = "hello";
  const char* world = "world";
  printf("%s %s\n", hello, world);
  for(size_t i=0; i < n; ++i) {
    for(size_t j=0; j < 10; ++j) {
      for(size_t k=0; k < 20; ++k) {
      }
    }
  }
}
int main(int argc, char* argv[]) {
  if(argc == 2) {
    subfunc(atoi(argv[1]));
  }
  return 0;
}
