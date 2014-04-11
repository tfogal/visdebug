package main;

import(
  "./bfd"
  "./cfg"
  "./debug"
  "fmt"
  "os"
  "syscall"
)

func procstatus(pid int, stat syscall.WaitStatus) {
  if stat.CoreDump() { panic("core dumped"); }
  if stat.Continued() { fmt.Printf("continued\n"); }
  if stat.Exited() {
    fmt.Printf("exited with status: %d\n", stat.ExitStatus())
  }
  if stat.Signaled() {
    fmt.Printf("received signal: %v\n", stat.Signal())
    panic("unexpected signal")
  }
  if stat.Stopped() {
    fmt.Printf("stopped with signal: %v\n", stat.StopSignal())
  }
  fmt.Printf("PID %d trap cause: %d\n", pid, stat.TrapCause())
}

func readsymbols(filename string) {
  desc, err := bfd.OpenR(filename, "");
  if err != nil {
    fmt.Printf("error opening bfd: %v\n", err);
    panic("bfd.OpenR");
  }
  symbols := bfd.Symbols(desc);
  if err = bfd.Close(desc) ; err != nil {
    fmt.Printf("error closing bfd: %v\n", err);
    panic("bfd.Close")
  }

  for _, symbol := range symbols {
    // skip internal symbols.
    if len(symbol.Name()) > 0 &&
       (symbol.Name()[0] == '.' || symbol.Name()[0] == '_') {
      continue;
    }
    fmt.Printf("0x%08x ", symbol.Address())
    flags := "";
    if(symbol.Local()) { flags += "LOCAL " } else { flags += "      " }
    if(symbol.Global()) { flags += "GLOBAL " } else { flags += "       " }
    if(symbol.Exported()) { flags += "EXPORT " } else { flags += "       " }
    if(symbol.Debug()) { flags += "DBG " } else { flags += "    " }
    if(symbol.Function()) { flags += "FQN " } else { flags += "    " }
    fmt.Printf("%s %s\n", flags, symbol.Name());
  }
}

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

type gfunc func(node *cfg.Node) ();
func inorder(graph map[uintptr]*cfg.Node, f gfunc) {
  seen := make(map[uintptr]bool)
  for k, v := range graph {
    if seen[k] { continue; }
    inorder_helper(v, seen, f)
    seen[k] = true
  }
}
func inorder_helper(node *cfg.Node, seen map[uintptr]bool, f gfunc) {
  if seen[node.Addr] { return }
  f(node)
  seen[node.Addr] = true
  for _, edge := range node.Edgelist {
    inorder_helper(edge.To, seen, f)
  }
}

func fqnroot(cflow map[uintptr]*cfg.Node, name string) (*cfg.Node) {
  for _, v := range cflow {
    if v.Name == name { return v }
  }
  return nil
}

func assert(condition bool) {
  if condition == false {
    panic("assertion failure")
  }
}

func main() {
  if len(os.Args) <= 1 {
    fmt.Println("which program?")
    return
  }
  program := os.Args[1:]
  readsymbols(program[0]);

  graph := cfg.CFG(program[0])
  { // debugging:
    nodecount := uint(0)
    inorder(graph, func(node *cfg.Node) { nodecount++ })
    assert(nnodes(graph) == nodecount)
  }
  //inorder(graph, func (node *cfg.Node) { fmt.Printf("%v\n", node); })

  fmt.Printf("sfunc: %s\n", fqnroot(graph, "subfunc").Name)

  proc, err := debug.StartUnderOurPurview(program[0], program)
  if err != nil {
    fmt.Printf("could not start program: %v\n", err)
    panic("failed starting proc")
  }

  var insns uint64
  insns = 0

  var wstat syscall.WaitStatus
  _, err = syscall.Wait4(proc.Pid, &wstat, 0, nil)
  if err != nil {
    fmt.Printf("wait4 error: %v\n", err)
    panic("wait")
  }

  for wstat.Stopped() {
    insns++;
    if wstat.Exited() { break }
    var regs syscall.PtraceRegs
    err = syscall.PtraceGetRegs(proc.Pid, &regs)
    if err != nil {
      fmt.Printf("get regs error: %v\n", err);
      break;
    }
    err = syscall.PtraceSingleStep(proc.Pid);
    if err != nil {
      panic("single step")
    }
    _, err = syscall.Wait4(proc.Pid, &wstat, 0, nil)
    if err != nil {
      fmt.Printf("wait4 error: %v\n", err)
      panic("wait")
    }
  }
  fmt.Printf("%d instructions\n", insns)
}
