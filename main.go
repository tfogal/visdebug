package main;

import(
  "./bfd"
  "./cfg"
  "flag"
  "fmt"
  "os"
  "syscall"
  "github.com/eaburns/ptrace"
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

var program string
var symlist bool
var execute bool
func init() {
  flag.StringVar(&program, "exec", "", "program to analyze/work with")
  flag.StringVar(&program, "e", "", "program to analyze/work with")
  flag.BoolVar(&symlist, "symbols", false, "print out the symbol table")
  flag.BoolVar(&symlist, "s", false, "print out the symbol table")
  flag.BoolVar(&execute, "x", false, "execute subprogram")
}

func main() {
  flag.Parse()
  if program == "" && flag.NArg() == 0 {
    fmt.Fprintf(os.Stderr, "No program given!\n")
    return
  }
  if program == "" { program = flag.Arg(0) }
  fmt.Printf("Using program '%s'\n", program)

  if symlist {
    readsymbols(program);
  }

  graph := cfg.CFG(program)
  { // debugging:
    nodecount := uint(0)
    inorder(graph, func(node *cfg.Node) { nodecount++ })
    assert(nnodes(graph) == nodecount)
  }
  //inorder(graph, func (node *cfg.Node) { fmt.Printf("%v\n", node); })

  // create a proper argv array that can be passed to exec(2)
  argv := make([]string, 1)
  argv[0] = program
  argv = append(argv, flag.Args()...)
  if len(argv) == 1 { argv = append(argv, argv[0]) }

  if execute {
    instrument(argv)
  }
}

func instrument(argv []string) {
  proc, err := ptrace.Exec(argv[0], argv)
  if err != nil {
    fmt.Printf("could not start program: %v\n", err)
    panic("failed starting proc")
  }

  insns := uint64(0)
  for _ = range proc.Events() {
    insns++
    err = proc.SingleStep()
    if err != nil {
      fmt.Fprintf(os.Stderr, "singlestep failed: %v\n", err)
    }
  }
  if err := proc.Error(); err != nil {
    fmt.Fprintf(os.Stderr, "error: %v\n", err)
  }
  fmt.Printf("%d instructions.\n", insns)
}
