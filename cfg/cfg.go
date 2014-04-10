package cfg;
// #include <stdlib.h>
// #include "gocfg.h"
// #cgo CXXFLAGS: -std=c++11
// #cgo CXXFLAGS: -Wall -Wextra -I/home/tfogal/sw/include
// #cgo LDFLAGS: -L/home/tfogal/sw/lib -lparseAPI -liberty -lz
import "C"
import "reflect"
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

func assert(conditional bool) {
  if false == conditional { panic("assertion failure") }
}

// Computes the control flow graph for the given program and returns it.  Does
// some basic filtering to get rid 'internal' symbols.
// Note that this memleaks a bit!  Do not call in a loop.
func CFG(program string) ([]CFGNode) {
  var c_nnodes C.size_t
  progname := C.CString(program);
  ccfg := C.cfg(progname, &c_nnodes);
  C.free(unsafe.Pointer(progname))
  nnodes := uint(c_nnodes)

  var gocfg []C.struct_node
  header := (*reflect.SliceHeader)(unsafe.Pointer(&gocfg))
  header.Cap = int(nnodes)
  header.Len = int(nnodes)
  header.Data = uintptr(unsafe.Pointer(ccfg))

  // convert the returned data into Go data.
  cfg := make([]CFGNode, nnodes)
  for i:=uint(0); i < nnodes; i++ {
    cfg[i].name = C.GoString(gocfg[i].name)
    cfg[i].addr = uintptr(gocfg[i].addr)
    nedges := uint(gocfg[i].edges)
    cfg[i].edgelist = make([]CFGEdge, nedges)

    // just like with gocfg, we need to create a go-indexable edge array.
    var goedgelist []C.struct_edge
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&goedgelist))
    hdr.Cap = int(nedges)
    hdr.Len = int(nedges)
    hdr.Data = uintptr(unsafe.Pointer(gocfg[i].edgelist))

    for e:=uint(0); i < nedges; i++ {
      cfg[i].edgelist[e].from = uintptr(goedgelist[e].from)
      assert(cfg[i].edgelist[e].from == cfg[i].addr)
      cfg[i].edgelist[e].to = uintptr(goedgelist[e].to)
      cfg[i].edgelist[e].flags = uint(goedgelist[e].flags)
    }
  }
  // now cleanup memory.
  for i:=uint(0); i < nnodes; i++ {
    C.free(unsafe.Pointer(gocfg[i].edgelist))
  }
  C.free(unsafe.Pointer(ccfg))

  return cfg
}
