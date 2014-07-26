#include <cinttypes>
#include <cstdlib>
#include <iostream>
#include <sys/types.h>
#include <unistd.h>

int
main(int argc, char* argv[]) {
  if(argc >= 2) {
    uint16_t* ptr = new uint16_t[atoi(argv[1])];
    std::cout << "got ptr: " << ptr << std::endl;
  }
  std::cout << "pid: " << (long)getpid() << std::endl;
  if(argc >= 2) {
    uint32_t* v = new uint32_t[atoi(argv[1])];
    std::cout << "got v: " << v << std::endl;
  }
  return 0;
}
