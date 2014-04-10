package cfg;
// #include <stdlib.h>
// #include "gocfg.h"
// #cgo CXXFLAGS: -std=c++11
// #cgo CXXFLAGS: -Wall -Wextra -I/home/tfogal/sw/include
// #cgo LDFLAGS: -L/home/tfogal/sw/lib -lparseAPI -liberty -lz
import "C"
import "unsafe"

type CFGEdge struct {
  from uintptr
  to uintptr
  flags uint
}
type CFGNode struct {
  addr uintptr
  name string // might be empty
  edgelist []CFGEdge
}

// Computes the control flow graph for the given program and returns it.  Does
// some basic filtering to get rid 'internal' symbols.
// Note that this memleaks a bit!  Do not call in a loop.
func CFG(program string) {
  progname := C.CString(program);
  var nnodes C.size_t
  abc := C.cfg(progname, &nnodes);
  C.free(unsafe.Pointer(progname))
  _ = abc;
}
