// This is not 'config', but rather 'c'ontrol 'f'low 'g'raph.
package cfg;
// #include <stdlib.h>
// #include "gocfg.h"
// #cgo CXXFLAGS: -std=c++11
// #cgo CXXFLAGS: -Wall -Wextra -I/home/tfogal/sw/include
// #cgo LDFLAGS: -L/home/tfogal/sw/lib -lparseAPI -liberty -lz
import "C"
import "bytes"
import "fmt"
import "reflect"
import "unsafe"

type Edge struct {
  To *Node
  flags uint
}
type Node struct {
  Name string // might be (often is) empty
  Addr uintptr
  Edgelist []*Edge
}

func (n *Node) String() string {
  buf := bytes.NewBufferString("")
  fmt.Fprintf(buf, "{'%s' 0x%08x [ ", n.Name, n.Addr)
  for _, edge := range n.Edgelist {
    fmt.Fprintf(buf, "0x%08x ", edge.To.Addr)
  }
  fmt.Fprintf(buf, "]}")
  return buf.String()
}

func assert(conditional bool) {
  if false == conditional { panic("assertion failure") }
}

// Computes the control flow graph for the given program and returns it.  Does
// some basic filtering to get rid 'internal' symbols.
// Note that this memleaks a bit!  Do not call in a loop.
func CFG(program string) (map[uintptr]*Node) {
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

  // convert the returned data into Go data.  Note this also does a
  // transformation from arrays-of-arrays to an actual graph structure.
  cfg := make(map[uintptr]*Node)

  for i:=uint(0); i < nnodes; i++ {
    addr := uintptr(gocfg[i].addr)
    nedges := uint(gocfg[i].edges)
    // the node could have been created as a target of a previous edge, but if
    // so then we didn't know anything about it...
    if cfg[addr] == nil {
      cfg[addr] = &Node{"", uintptr(0), nil}
    }
    // ... so we need to fill that stuff in anyway.
    cfg[addr].Name = C.GoString(gocfg[i].name)
    cfg[addr].Addr = addr
    cfg[addr].Edgelist = make([]*Edge, nedges)

    // just like with gocfg, we need to create a go-indexable edge array.
    var goedgelist []C.struct_edge
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&goedgelist))
    hdr.Cap = int(nedges)
    hdr.Len = int(nedges)
    hdr.Data = uintptr(unsafe.Pointer(gocfg[i].edgelist))

    for e:=uint(0); e < nedges; e++ {
      dest := uintptr(goedgelist[e].to)
      // if we don't already have a node for this edge, create a temporary one.
      // At another iteration through our outer loop, we'll see the address
      // again and fill in the other parts.
      if cfg[dest] == nil {
        cfg[dest] = &Node{Name: "", Addr: dest, Edgelist: nil}
      }
      cfg[addr].Edgelist[e] = &Edge{
        To: cfg[dest],
        flags: uint(goedgelist[e].flags),
      }
      assert(addr == uintptr(goedgelist[e].from))
    }
  }

  // now cleanup memory.
  for i:=uint(0); i < nnodes; i++ {
    C.free(unsafe.Pointer(gocfg[i].edgelist))
  }
  C.free(unsafe.Pointer(ccfg))

  return cfg
}

// returns true if the node 'target' is reachable from 'from'.
func Reachable(target *Node, from *Node) (bool) {
  seen := make(map[uintptr]bool)
  return reachable(target, from, seen)
}

func reachable(target *Node, from *Node, seen map[uintptr]bool) (bool) {
  if seen[from.Addr] { return false }
  seen[from.Addr] = true
  for _, edge := range from.Edgelist {
    if edge.To == target || reachable(target, edge.To, seen) {
      return true
    }
  }
  return false
}

// reachable in a single step
func reachable1(target *Node, from *Node) (bool) {
  for _, edge := range from.Edgelist {
    if edge.To == target { return true }
  }
  return false
}

func reachable2(target *Node, from *Node) (bool) {
  for _, edge1 := range from.Edgelist {
    node1 := edge1.To
    for _, edge2 := range node1.Edgelist {
      if edge2.To == target { return true }
    }
  }
  return false
}

func reachable3(target *Node, from *Node) (bool) {
  for _, edge1 := range from.Edgelist {
    node1 := edge1.To
    for _, edge2 := range node1.Edgelist {
      node2 := edge2.To
      for _, edge3 := range node2.Edgelist {
        if edge3.To == target { return true }
      }
    }
  }
  return false
}
