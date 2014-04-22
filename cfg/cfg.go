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
import "math"
import "reflect"
import "unsafe"

const(
  cfg_INLOOP = (1 << 0)
)

type Edge struct {
  To *Node
  flags uint
}
type Node struct {
  Name string // might be (often is) empty
  Addr uintptr
  Edgelist []*Edge
  flags uint
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
      cfg[addr] = &Node{"", uintptr(0), nil, 0}
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

func LoopCalc(root *Node) {
  seen := make(map[uintptr]bool)
  loopcalc(root, seen)
}
func loopcalc(from* Node, seen map[uintptr]bool) {
  if seen[from.Addr] { return }
  seen[from.Addr] = true
  for _, edge := range from.Edgelist {
    if Reachable(from, edge.To) {
      from.flags |= cfg_INLOOP
    }
    loopcalc(edge.To, seen)
  }
}
func (n *Node) InLoop() (bool) { return n.flags & cfg_INLOOP > 0 }

// counts the number of edges to 'target' from 'source'.  The 'source' edge
// counts, so this is positive---or unreachable, which gives 0.
func LoopDist(target *Node, source *Edge) (uint) {
  seen := make(map[uintptr]bool)
  return loopdist(target, source, seen)
}

func minu(a uint, b uint) (uint) {
  if a < b {
    return a
  }
  return b
}
/* valid value predicate */
type vvaluep func(value uint) (bool)

/* minimum for a vector of uint values, but accepts a predicate to determine
 * whether a value is 'valid' or not. */
func minuvp(values []uint, predicate vvaluep) (uint) {
  ret := uint(math.MaxUint64)
  for _, v := range values {
    if predicate(v) {
      ret = minu(ret, v)
    }
  }
  return ret
}

func loopdist(target *Node, edge *Edge, seen map[uintptr]bool) (uint) {
  if seen[edge.To.Addr] { return 0 }
  seen[edge.To.Addr] = true

  if edge.To.Addr == target.Addr {
    return 1
  }

  // Is edge.To a leaf node?  Then 'ya can't get thar from here', as the
  // Maineacs say.
  if len(edge.To.Edgelist) == 0 { return 0 }

  // the distance is 1+the distance from the node 'edge' points to.
  // but 'edge.To' can have any number of outward edges, so there could be
  // multiple paths to 'target'.  Compute the target along each edge.
  distances := make([]uint, len(edge.To.Edgelist))
  for i, subedge := range edge.To.Edgelist {
    // we can't do 1+ here because we filter out the 0's later.
    distances[i] = loopdist(target, subedge, seen)
  }
  nonzero := func(value uint) (bool) { return value > 0 }
  /* the /shortest/ path is the one we want to report.
   * also, don't forget the "1+" part! */
  return 1 + minuvp(distances, nonzero)
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
