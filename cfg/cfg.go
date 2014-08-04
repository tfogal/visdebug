// This is not 'config', but rather 'c'ontrol 'f'low 'g'raph.
package cfg;
// #include <stdlib.h>
// #include "gocfg.h"
// #cgo CXXFLAGS: -std=c++11
// #cgo CXXFLAGS: -Wall -Wextra -I/home/tfogal/sw/include
// #cgo LDFLAGS: -L/home/tfogal/sw/lib -lparseAPI -lsymLite -lz
import "C"
import "bytes"
import "fmt"
import "math"
import "reflect"
import "unsafe"

const(
  loopHeader = 1 << iota
  loopBody   = 1 << iota // body and header are not exclusive (nested loops)
  entry      = 1 << iota // entry point of a function
  exit       = 1 << iota
)

// set for keeping track of per-node dominance.  all corresponding functions
// never modify a set: they instead return a new set with the appropriate
// semantics.
type domset struct {
  set map[uintptr]bool
}

func (d *domset) Len() uint { return uint(len(d.set)); }

type Edge struct {
  To *Node
  flags uint
}
type Node struct {
  Name string // might be (often is) empty
  Addr uintptr
  Edgelist []*Edge
  flags uint
  dominators domset
  depth uint
}
func makeNode(name string, addr uintptr) (*Node) {
  return &Node{name, addr, nil, 0, nullset(), 0}
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

// converts the C graph structure into a Go graph structure.  Takes ownership
// of 'ccfg' and deallocates it.
func go_graph(ccfg *C.struct_node, nnodes uint) (map[uintptr]*Node) {
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
      cfg[addr] = makeNode("", uintptr(0))
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
        cfg[dest] = makeNode("", dest)
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

// Computes the control flow graph for the given program and returns it.  Does
// some basic filtering to get rid 'internal' symbols.
// Note that this memleaks a bit (C++ lib is broken)!  Do not call in a loop.
func Build(program string) (map[uintptr]*Node) {
  var c_nnodes C.size_t
  progname := C.CString(program);
  ccfg := C.cfg(progname, &c_nnodes);
  C.free(unsafe.Pointer(progname))
  nnodes := uint(c_nnodes)
  return go_graph(ccfg, nnodes)
}

// Computes the LOCAL (to a function) control flow graph.
// todo: return a single node? a single function should only have one entry.
// Note that this memleaks a bit (C++ lib is broken)!  Do not call in a loop.
func Local(program string, function string) (map[uintptr]*Node) {
  var c_nnodes C.size_t
  progname := C.CString(program);
  funcname := C.CString(function)
  ccfg := C.cfgLocal(progname, funcname, &c_nnodes)
  C.free(unsafe.Pointer(progname))
  C.free(unsafe.Pointer(funcname))
  nnodes := uint(c_nnodes)
  return go_graph(ccfg, nnodes)
}

// returns true if the node 'target' is reachable from 'from'.
func Reachable(target *Node, from *Node) (bool) {
  seen := make(map[uintptr]bool)
  return reachable(target, from, seen)
}

// internal helper function for 'Reachable'.
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

func identify_loops(root *Node) {
  seen := make(map[uintptr]bool)
  id_loops_helper(root, seen)
}
func id_loops_helper(from* Node, seen map[uintptr]bool) {
  if seen[from.Addr] { return }
  seen[from.Addr] = true
  for _, edge := range from.Edgelist {
    if Reachable(from, edge.To) {
      from.flags |= loopBody
    }
    id_loops_helper(edge.To, seen)
  }
}
func (n *Node) InLoop() bool { return (n.flags & loopBody) > 0 }
func (n *Node) LoopHeader() bool { return (n.flags & loopHeader) > 0 }
// returns the loop depth that the basic block is in.  our depth calculations
// start at 1, so we remove one to make loop depth == dimensionality.
func (n *Node) Depth() uint { return n.depth-1 }

// counts the number of edges to 'target' from 'source'.  The 'source' edge
// counts, so this is positive---or unreachable, which gives 0.
func loop_distance(target *Node, source *Edge) (uint) {
  seen := make(map[uintptr]bool)
  return loop_dist(target, source, seen)
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

func loop_dist(target *Node, edge *Edge, seen map[uintptr]bool) (uint) {
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
    distances[i] = loop_dist(target, subedge, seen)
  }
  nonzero := func(value uint) (bool) { return value > 0 }
  /* the /shortest/ path is the one we want to report.
   * also, don't forget the "1+" part! */
  return 1 + minuvp(distances, nonzero)
}

func nullset() (domset) {
  var dom domset
  dom.set = make(map[uintptr]bool)
  return dom
}
// unions the two sets together.
func union(a domset, b domset) (domset) {
  var dom domset
  dom.set = make(map[uintptr]bool, len(a.set) + len(b.set))
  for ptr, _ := range a.set {
    dom.set[ptr] = true
  }
  for ptr, _ := range b.set {
    dom.set[ptr] = true
  }
  return dom
}
func intersection(a domset, b domset) (domset) {
  var result domset
  result.set = make(map[uintptr]bool)
  for ptrA, _ := range a.set {
    _, found := b.set[ptrA]
    if found {
      result.set[ptrA] = true
    }
  }
  return result
}
func exclude(a domset, elem uintptr) (domset) {
  null := nullset()
  dom := union(a, null) // basically 'copy a'
  delete(dom.set, elem)
  return dom
}
// construct a singleton set out of the given pointer.
func set(address uintptr) (domset) {
  dom := nullset()
  dom.set[address] = true
  return dom
}
func sameset(a domset, b domset) (bool) {
  return len(intersection(a,b).set) == len(a.set)
}

// Analyzes a graph, computing all the properties we can.
func Analyze(root *Node) {
  dominance(root)
  headers(root)
  depth(root)
}

// an edge with both from and to nodes.  sometimes we need to get in-edges,
// which is a huge PITA with our current graph structure.
type biEdge struct {
  From, To *Node
  flags uint
}
// creates an alternate representation of the graph rooted at 'root', based
// solely on the edges.
func build_edgelist(root *Node) []biEdge {
  seen := make(map[uintptr]bool)
  return build_edgelist_helper(root, seen)
}
func build_edgelist_helper(node *Node, seen map[uintptr]bool) []biEdge {
  if seen[node.Addr] { return nil }
  seen[node.Addr] = true

  elist := make([]biEdge, 0)
  for _, e := range node.Edgelist {
    be := biEdge{From: node, To: e.To, flags: e.flags}
    elist = append(elist, be)

    el := build_edgelist_helper(e.To, seen)
    elist = append(elist, el...)
  }
  return elist
}

// iterates through the graph, identifying which basic blocks are loop headers.
// returns nothing: modifies the graph's flags.
func headers(root *Node) {
  elist := build_edgelist(root)
  seen := make(map[uintptr]bool)
  headers_helper(root, seen, elist)
}
func headers_helper(node *Node, seen map[uintptr]bool, elist []biEdge) {
  if seen[node.Addr] { return }
  seen[node.Addr] = true

  // a loop header is a basic block with 2 in-edges and 2 out-edges that is
  // reachable from one or both of those out-edges.
  // TODO: switch statements seem to produce duplicate BS edges; we will need
  // to filter those out for this analysis to be valid.
  // TODO: above definition is invalid in the presence of gotos.  Do we care?
  in, out := in_edges(node, elist), out_edges(node, elist)
  if in == 2 && out == 2 {
    if Reachable(node, node.Edgelist[0].To) ||
       Reachable(node, node.Edgelist[1].To) {
      node.flags |= loopHeader
    }
  }
  for _, e := range node.Edgelist { // recurse.
    headers_helper(e.To, seen, elist)
  }
}

// counts the number of edges which lead in to 'node'.
func in_edges(node *Node, elist []biEdge) uint {
  n := uint(0)
  for _, e := range elist {
    if e.To == node { n++ }
  }
  return n
}
// counts the number of edges which lead out of 'node'.
func out_edges(node *Node, elist []biEdge) uint {
  n := uint(0)
  for _, e := range elist {
    if e.From == node { n++ }
  }
  // we don't actually need 'elist' for this.  But it's a good check to make
  // sure it has the right number of edges in it.
  if n != uint(len(node.Edgelist)) {
    panic("number of edges differs; build_edgelist is probably broken.")
  }
  return n
}

// calculates the depth of each basic block.  requires dominance sets to have
// already been computed!
func depth(root *Node) {
  seen := make(map[uintptr]bool)
  elist := build_edgelist(root)
  depthcalc_helper(root, seen, elist)
}
// finds the node at the associated address.
func addr_to_node(address uintptr, elist []biEdge) *Node {
  for _, e := range elist {
    if e.From.Addr == address { return e.From }
    if e.To.Addr == address { return e.To }
  }
  return nil
}
func depthcalc_helper(node *Node, seen map[uintptr]bool, elist []biEdge) {
  if seen[node.Addr] { return }
  seen[node.Addr] = true

  // in any sort of reasonable program, this should never happen. it really
  // just means our client code is being dumb and computing this twice. not
  // really an error, but very stupid, so let's not panic but still warn.
  if node.depth != 0 {
    fmt.Printf("depth previously calculated?  resetting depth.\n")
    node.depth = 0
  }
  // the depth of a block is the depth of the most-enclosing loop header, +1
  max_depth := uint(0)
  for d := range node.dominators.set {
    n := addr_to_node(d, elist)
    if n == nil { panic("node not found!") } // dominator is not in graph??
    // nodes dominate themself, but that doesn't tell us anything, here.
    if n.Addr == node.Addr { continue }
    // Remove all dominators except the one under consideration
    // when performing the reachability analysis. this filters out
    // the 'exit' branches of loop conditionals, so that they are only
    // considered as part of "higher" loops.
    other_doms := exclude(node.dominators, d)
    delete(other_doms.set, node.Addr)
    if n.LoopHeader() && reachable(n, node, other_doms.set) {
      if n.depth > max_depth { max_depth = n.depth }
    }
  }
  node.depth = max_depth + 1
  for _, e := range node.Edgelist {
    depthcalc_helper(e.To, seen, elist)
  }
}

// calculates the dominance set for every node in the graph.  modifies the
// graph itself.
func dominance(root* Node) {
  // initialize root node's dominance set to just be itself.
  root.dominators = set(root.Addr)
  // now recurse on root's children.
  for _, edge := range root.Edgelist {
    dominance_helper(edge.To, root)
  }
}
/* recursive dominance calculation.  this computation is a bit different than
 * the way the algorithm is normally formulated.  textbooks tend to define this
 * in terms of a corresponding 'predecessor' set, which is the set of all nodes
 * which lead to the node given as argument.  However, since our edges are
 * one-way, computing the predecessor set from the node itself is difficult in
 * most cases and impossible in others.
 * If you think of the classic algorithm as 'backward propagating', then this
 * is 'forward propagating'.  It is less efficient than the O(n^2) achievable
 * normally: In the presence of cycles, we will visit each node in the cycle
 * n_{cycles} times.  Not a big deal for us.
 * The gist of it is that we only recurse when something changes.  The first
 * time through the graph is, however, a special case in which something always
 * changes. */
func dominance_helper(chld *Node, parent *Node) {
  incoming := union(parent.dominators, set(chld.Addr))
  if sameset(chld.dominators, nullset()) { // first time we're here, init.
    chld.dominators = incoming
  } else {
    // we've been here before.  will our update change anything?
    if sameset(chld.dominators, intersection(chld.dominators, incoming)) {
      // if it won't change anything, then bail.
      return
    }
    chld.dominators = intersection(chld.dominators, incoming)
  }
  for _, edge := range chld.Edgelist { // calc dominance of children
    dominance_helper(edge.To, chld)
  }
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
