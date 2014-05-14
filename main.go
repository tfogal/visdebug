package main;

import(
  "bufio"
  "errors"
  "flag"
  "fmt"
  "os"
  "strings"
  "syscall"
  "github.com/tfogal/ptrace"
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
  args []string
}
func (c cgeneric) Execute(proc *ptrace.Tracee) (error) {
  fmt.Printf("cmd: %s\n", c.args)
  return nil
}
type ccontinue struct {
  args []string
}
type cparseerror struct {}
func (c cparseerror) Execute(proc *ptrace.Tracee) (error) {
  fmt.Fprintf(os.Stderr, "error parsing command.\n")
  return errors.New("Parsing")
}
func (c ccontinue) Execute(proc *ptrace.Tracee) (error) {
  fmt.Printf("continuing ... %v\n", c.args)
  err := proc.Continue()
  return err
}
type cstep struct{} // needs no args.
func (c cstep) Execute(proc *ptrace.Tracee) (error) {
  err := proc.SingleStep()
  return err
}
type cstop struct{}
func (c cstop) Execute(proc *ptrace.Tracee) (error) {
  err := proc.SendSignal(syscall.SIGSTOP)
  return err
}
type cpid struct{}
func (c cpid) Execute(proc *ptrace.Tracee) (error) {
  fmt.Printf("%d\n", proc.PID())
  return nil
}
type cstatus struct{}
func (c cstatus) Execute(proc *ptrace.Tracee) (error) {

  fn := fmt.Sprintf("/proc/%d/stat", proc.PID())
  file, err := os.Open(fn)
  if err != nil { return err }
  defer file.Close()
  var pid int
  var name string
  var state rune
  n, err := fmt.Fscanf(file, "%d %s %c", &pid, &name, &state)
  if err != nil { return err }
  if n <= 1 {
    return errors.New("could not scan enough")
  }
  fmt.Printf("process %d is ", proc.PID())
  switch(state) {
    case 'D': fmt.Printf("uninterruptible sleep (io?)\n"); break
    case 'R': fmt.Printf("running\n"); break
    case 'S': fmt.Printf("sleeping\n"); break
    case 't': fmt.Printf("stopped (tracing)\n"); break
    case 'W': fmt.Printf("(impossibly) paging\n"); break
    case 'X': fmt.Printf("(impossibly) dead\n"); break
    case 'Z': fmt.Printf("awaits reaping.\n"); break
    default: fmt.Printf("unknown?!\n"); break
  }
  return nil
}
type cquit struct{}
func (c cquit) Execute(proc *ptrace.Tracee) (error) {
  if err := proc.SendSignal(syscall.SIGKILL) ; err != nil {
    return err
  }
  return nil
}

func parse_cmdline(line string) (Command) {
  tokens := strings.Split(line, " ")
  if len(tokens) == 0 { return cparseerror{} }
  switch(tokens[0]) {
    case "cont": fallthrough
    case "continue": return ccontinue{tokens[1:len(tokens)]}
    case "pid": return cpid{}
    case "quit": fallthrough
    case "exit": return cquit{}
    case "stat": fallthrough
    case "status": return cstatus{}
    case "step": return cstep{}
    case "break": return cstop{} // opposite of 'continue' :-)
    default: return cgeneric{tokens}
  }
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
      cmd := parse_cmdline(strings.TrimSpace(s))
      cmds <- cmd
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

  events := proc.Events()
  fmt.Println("Please state the nature of the debugging emergency.")

  cmds <- nil
  for {
    select {
      case status := <-events:
        if status == nil {
          proc.Close()
          close(cmds)
          return
        }
        if status.(syscall.WaitStatus).Exited() {
          fmt.Println("\nprogram terminated.")
          proc.Close()
          close(cmds)
          return
        }
      case cmd := <-cmds:
        if err := cmd.Execute(proc) ; err != nil {
          fmt.Fprintf(os.Stderr, "error executing command: %v\n", err)
        }
        cmds <- nil // signal that receiver can output && read next command
    }
  }
}
