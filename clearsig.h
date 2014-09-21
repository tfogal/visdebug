#include <unistd.h>

// Go does not export a SETSIGINFO command.  So we do it manually by just
// calling some custom C code.
extern int clearsignal(long pid);
