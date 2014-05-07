package main;

import(
  "bufio"
  "flag"
  "fmt"
  "os"
  "strings"
  "syscall"
  "github.com/eaburns/ptrace"
  "./bfd"
  "./cfg"
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

func lerp(val uint, imin uint,imax uint, omin uint,omax uint) (uint) {
  assert(imin < imax)
  assert(omin < omax)
  return uint(float64(omin) + float64(val-imin) *
                              float64(omax-omin) / float64(imax-imin))
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

var program string
var symlist bool
var execute bool
var dotcfg bool
func init() {
  flag.StringVar(&program, "exec", "", "program to analyze/work with")
  flag.StringVar(&program, "e", "", "program to analyze/work with")
  flag.BoolVar(&symlist, "symbols", false, "print out the symbol table")
  flag.BoolVar(&symlist, "s", false, "print out the symbol table")
  flag.BoolVar(&execute, "x", false, "execute subprogram")
  flag.BoolVar(&dotcfg, "cfg", false, "compute and print CFG")
}

func basename(s string) (string) {
  if i := strings.LastIndex(s, "/"); i != -1 {
    return s[i+1:]
  }
  return s
}

func main() {
  flag.Parse()
  if program == "" && flag.NArg() == 0 {
    fmt.Fprintf(os.Stderr, "No program given!\n")
    return
  }
  if program == "" { program = flag.Arg(0) }

  if symlist {
    readsymbols(program);
  }

  if(dotcfg) {
    graph := cfg.CFG(program)
    root := findNodeByName(graph, "main")
    assert(root != nil)
    cfg.Dominance(root)
    fmt.Printf("digraph %s {\n", basename(program))
    inorder(graph, dotNode)
    fmt.Println("}");
  }

  // create a proper argv array that can be passed to exec(2)
  argv := make([]string, 1)
  argv[0] = program
  argv = append(argv, flag.Args()...)
  if len(argv) == 1 { argv = append(argv, argv[0]) }

  if execute {
    instrument(argv)
  }
}

type Command interface{
  Execute(*ptrace.Tracee) (error)
}
type cgeneric struct {
  args string
}
func (c cgeneric) Execute(proc *ptrace.Tracee) (error) {
  fmt.Printf("cmd: %s\n", c.args)
  return nil
}
func commands() (chan Command) {
  cmds := make(chan Command)
  go func() {
    rdr := bufio.NewReader(os.Stdin)
    for {
      <- cmds // wait for 'green light' from our parent.
      fmt.Printf("> ")
      os.Stdout.Sync()
      s, err := rdr.ReadString('\n')
      if err != nil {
        fmt.Fprintf(os.Stderr, "error scanning line: %v\n", err)
        cmds <- nil
        close(cmds)
        return
      }
      cgen := cgeneric{strings.TrimSpace(s)}
      cmds <- cgen
    }
  }()
  return cmds
}

func instrument(argv []string) {
  proc, err := ptrace.Exec(argv[0], argv)
  if err != nil {
    fmt.Printf("could not start program: %v\n", err)
    panic("failed starting proc")
  }

  cmds := commands()
  cmds <- nil

  events := proc.Events()

  insns := uint64(0)
  for {
    select {
      case status := <-events:
        if syscall.WaitStatus(status).Exited() {
          fmt.Printf("\nprogram terminated.  %d instructions.\n", insns)
          return
        }
        insns++
        if err := proc.SingleStep() ; err != nil {
          fmt.Fprintf(os.Stderr, "single stepping failed: %v\n", err)
          return
        }
      case cmd := <-cmds:
        cmd.Execute(proc)
        cmds <- nil
    }
  }
}
