// "dbg" is a collection of stuff which is not really needed.  these functions
// are often thrown into a code path as an ad hoc way of verifying that things
// work the way we expect.
package main

import "bufio"
import "fmt"
import "log"
import "os"
import "syscall"
import "./bfd"
import "./cfg"
import "github.com/tfogal/ptrace"

// follows RSP a couple times and prints it out; a crude stack trace.
func print_walkstack(inferior *ptrace.Tracee) {
  regs, err := inferior.GetRegs()
  if(err != nil) { log.Fatalf(err.Error()) }

  for i:=uint64(0); i < 2; i++ {
    deref, err := inferior.ReadWord(uintptr(regs.Rsp+(i*8)))
    if err != nil { log.Fatalf(err.Error()) }
    fmt.Printf("[go] rsp-%d (0x%0x): 0x%0x\n", i*8, regs.Rsp+(i*8), deref)
  }
}

// reads symbols and prints out the address for the symbols we care about most.
func print_symbol_info(inferior *ptrace.Tracee) {
  symbols, err := bfd.SymbolsProcess(inferior)
  if err != nil {
    log.Fatalf("could not read inferior's symbols: %v\n", err)
  }
  symmalloc := symbol("malloc", symbols)
  if symmalloc == nil { log.Fatalf("could not find malloc symbol") }

  n := 0
  for _, v := range symbols {
    if v.Name() == "malloc" {
      n++
      fmt.Printf("malloc @ 0x%0x\n", v.Address())
    }
  }
  fmt.Printf("There are %d 'malloc's in the symbol table.\n", n)
  symcalloc := symbol("calloc", symbols)
  if symcalloc == nil { log.Fatalf("could not find calloc symbol") }
  fmt.Printf("calloc is at: 0x%x\n", symcalloc.Address())
  fmt.Printf("malloc is at: 0x%x\n", symmalloc.Address())
}

// attaches to the PID given by the first argument and prints out the symbols
// of that process.
func print_address_info(argv []string) {
  var pid int
  fmt.Sscanf(argv[0], "%d", &pid)
  fmt.Printf("attaching to %d\n", pid)
  inferior, err := ptrace.Attach(pid)
  if err != nil {
    log.Fatalf("could not start program: %v", err)
  }
  eatstatus(<-inferior.Events()) // 'process stopped' due to attach.
  print_symbol_info(inferior)

  inferior.Detach()
  inferior.Close()
}

// count the number of nodes in a graph.
func nnodes(graph map[uintptr]*cfg.Node) (uint) {
  seen := make(map[uintptr]bool)
  nodes := uint(0)
  for k, _ := range graph {
    if seen[k] { continue; }
    seen[k] = true
    nodes++
  }
  return nodes
}

// a function on a CFG node.
type gfunc func(node *cfg.Node) ();

// performs an inorder traversal of the given graph, executing 'f' on each node.
func inorder(graph map[uintptr]*cfg.Node, f gfunc) {
  seen := make(map[uintptr]bool)
  for k, v := range graph {
    if seen[k] { continue; }
    inorder_helper(v, seen, f)
    seen[k] = true
  }
}
// inorder traversal of a graph, internal implementation.  this exists so that
// users don't need to create the map that keeps track of which nodes have been
// visited.
func inorder_helper(node *cfg.Node, seen map[uintptr]bool, f gfunc) {
  if seen[node.Addr] { return }
  f(node)
  seen[node.Addr] = true
  for _, edge := range node.Edgelist {
    inorder_helper(edge.To, seen, f)
  }
}

// returns true iff this node has a child that points back to it.
func loop1d(node *cfg.Node) (bool) {
  for _, edge := range node.Edgelist {
    target := edge.To
    for _, childedge := range target.Edgelist {
      if childedge.To.Addr == node.Addr {
        return true;
      }
    }
  }
  return false;
}

// prints out a node in 'dot' notation.
func dotNode(node *cfg.Node) {
  fmt.Printf("\t\t\"0x%08x\" [", node.Addr)
  if(node.Name != "") {
    fmt.Printf("label = \"%s\", ", node.Name)
  }
  col := lerp(node.Dominators.Len(), 0,25, 0,255)
  assert(col <= 255)
  if(node.Dominators.Len() == 0) {
    fmt.Printf("color=\"#ff0000\"");
  } else {
    fmt.Printf("color=\"#00%x00\"", col)
  }
  fmt.Printf("];\n");

  for _, edge := range node.Edgelist {
    fmt.Printf("\t\t\"0x%08x\" -> \"0x%08x\";\n", node.Addr, edge.To.Addr)
  }
}

func findNodeByName(graph map[uintptr]*cfg.Node, name string) (*cfg.Node) {
  seen := make(map[uintptr]bool)
  for k, v := range graph {
    node := find_helper(v, seen, name)
    if node != nil && node.Name == name { return node }
    seen[k] = true
  }
  return nil
}
func
find_helper(node *cfg.Node, seen map[uintptr]bool, name string) (*cfg.Node) {
  if seen[node.Addr] { return nil }
  if node.Name == name { return node }
  seen[node.Addr] = true
  for _, edge := range node.Edgelist {
    found := find_helper(edge.To, seen, name)
    if found != nil && found.Name == name { return found }
  }
  return nil
}

// linear interpolate
func lerp(val uint, imin uint,imax uint, omin uint,omax uint) (uint) {
  assert(imin < imax)
  assert(omin < omax)
  return uint(float64(omin) + float64(val-imin) *
                              float64(omax-omin) / float64(imax-imin))
}

func whereis(inferior *ptrace.Tracee) uintptr {
  iptr, err := inferior.GetIPtr()
  if err != nil { log.Fatalf("get insn ptr failed: %v\n", err) }

  return iptr
}

func eatstatus(stat ptrace.Event) {
  status := stat.(syscall.WaitStatus)
  fmt.Printf("[go] eating ")
  if status.Stopped() { fmt.Println("'stop' event") }
  if status.Continued() { fmt.Println("'continue' event") }
  if status.Signaled() { fmt.Printf("'%v' signal\n", status.Signal()) }
  if status.Exited() { fmt.Printf("exited event.\n") }
}

// prints out the contents of the given process' maps.  used for debugging
// free_space_address.
func viewmaps(pid int) {
  filename := fmt.Sprintf("/proc/%d/maps", pid)
  maps, err := os.Open(filename)
  if err != nil {
    panic(err)
  }
  defer maps.Close()

  scanner := bufio.NewScanner(maps)
  for scanner.Scan() {
    fmt.Println(scanner.Text())
  }
}
