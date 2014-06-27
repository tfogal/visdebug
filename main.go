package main;

import(
  "bufio"
  "errors"
  "flag"
  "fmt"
  "io"
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

var symlist bool
var execute bool
var dotcfg bool
var showmallocs bool
func init() {
  flag.BoolVar(&symlist, "symbols", false, "print out the symbol table")
  flag.BoolVar(&symlist, "s", false, "print out the symbol table")
  flag.BoolVar(&execute, "x", false, "execute subprogram")
  flag.BoolVar(&dotcfg, "cfg", false, "compute and print CFG")
  flag.BoolVar(&showmallocs, "mallocs", false, "print a line per malloc")
}

func basename(s string) (string) {
  if i := strings.LastIndex(s, "/"); i != -1 {
    return s[i+1:]
  }
  return s
}

func main() {
  flag.Parse()
  if flag.NArg() == 0 {
    fmt.Fprintf(os.Stderr, "No program given!\n")
    return
  }
  argv := flag.Args()
  if len(argv) == 1 { panic("no arguments?") }

  if symlist {
    readsymbols(argv[0]);
  }

  if(dotcfg) {
    graph := cfg.CFG(argv[0])
    root := findNodeByName(graph, "main")
    assert(root != nil)
    cfg.Dominance(root)
    fmt.Printf("digraph %s {\n", basename(argv[0]))
    inorder(graph, dotNode)
    fmt.Println("}");
  }

  if execute {
    instrument(argv)
  }
  if showmallocs {
    mallocs(argv)
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
        cmds <- nil // signal EOF.
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

const SYNCFILE string = "/tmp/.garbage";
func wait_for_0() {
  v := uint(42)
  fmt.Printf("[Go] Waiting for 0 in %s...\n", SYNCFILE)
  for v != 0 {
    fp, err := os.Open(SYNCFILE)
    if err != nil { fp.Close(); continue; }
    v = 42
    _, err = fmt.Fscanf(fp, "%d", &v)
    if err != nil && err != io.EOF { fp.Close(); panic(err) }
    fp.Close()
  }
  fmt.Printf("[Go] got the 0, moving on..\n")
}
func write_1() {
  fmt.Printf("[Go] Writing 1 into %s\n", SYNCFILE)
  fp, err := os.OpenFile(SYNCFILE, os.O_RDWR | os.O_CREATE | os.O_TRUNC, 0666)
  if err != nil { panic(err) }
  _, err = fmt.Fprintf(fp, "%d\n", 1)
  if err != nil { panic(err) }
  fp.Close()
}
// Write a '1' into /tmp/.garbage and then close it.
// Pause execution until /tmp/.garbage reads '0'.
func badsync() {
  wait_for_0()
  write_1()
}

func symbol(symname string, symbols []bfd.Symbol) *bfd.Symbol {
  for _, sym := range symbols {
    if sym.Name() == symname {
      return &sym
    }
  }
  return nil
}

func whereis(inferior *ptrace.Tracee) uintptr {
  iptr, err := inferior.GetIPtr()
  if err != nil { panic(fmt.Errorf("get insn ptr failed: %v\n", err)) }

  return iptr
}

func wait_for_breakpoint(inferior *ptrace.Tracee, address uintptr) error {
  // we only need to change one byte, but we need to write a word.  thus we'll
  // need to read the whole word and replace just the byte we care about.
  insn, err := inferior.ReadWord(address)
  if err != nil { return err }
  const imask = 0xffffffffffffff00
  bp := (insn & imask) | 0xcc // 0xcc is "the" breakpoint opcode.

  // overwrite with breakpoint (0xcc)
  err = inferior.WriteWord(address, bp)
  if err != nil { return err }

  // if you love something, set it free ...
  if err = inferior.Continue() ; err != nil {
    return fmt.Errorf("child could not continue: %v", err)
  }

  stat := <- inferior.Events() // ... it will come back, if it's meant to be.
  status := stat.(syscall.WaitStatus)
  if status.Exited() { return io.EOF }
  if status.CoreDump() {
    return errors.New("abnormal termination, core dumped")
  }
  if status.StopSignal() != syscall.SIGTRAP {
    return fmt.Errorf("unexpected signal %d\n", status.StopSignal())
  }

  // restore the correct instruction ...
  newinsn, err := inferior.ReadWord(address)
  if err != nil { return err }

  err = inferior.WriteWord(address, (newinsn & imask) | (insn & 0xFF))
  if err != nil { return fmt.Errorf("could not restore insn: %v\n", err) }

  // ... back up the instruction pointer, and ...
  iptr, err := inferior.GetIPtr()
  if err != nil { return fmt.Errorf("could not get insn ptr: %v\n", err) }
  err = inferior.SetIPtr(iptr - 1)
  if err != nil { return fmt.Errorf("could not set insn pointer: %v\n", err) }

  // ... execute the 'call'.
  if err = inferior.SingleStep() ; err != nil {
    return fmt.Errorf("could not step through call: %v", err)
  }

  stat = <- inferior.Events() // eat the trap we get from single stepping
  status = stat.(syscall.WaitStatus)
  if !status.Stopped() || status.StopSignal() != syscall.SIGTRAP {
    procstatus(inferior.PID(), status)
    return fmt.Errorf("expecting sigtrap, got %d instead!", status)
  }

  return nil
}

func mallocs(argv []string) {
  inferior, err := ptrace.Exec(argv[0], argv)
  if err != nil {
    panic(fmt.Errorf("could not start program: %v", err))
  }

  <- inferior.Events() // eat initial 'process is starting' notification.
  if err = os.Remove(SYNCFILE) ; err != nil {
    fmt.Fprintf(os.Stderr, "[Go] error removing %s! %v\n", SYNCFILE, err)
  }
  if err = inferior.Continue() ; err != nil {
    panic(fmt.Errorf("error letting inferior start: %v", err))
  }
  wait_for_0()
  if err = inferior.SendSignal(syscall.SIGSTOP) ; err != nil {
    panic(fmt.Errorf("could not stop inferior: %v\n", err))
  }
  stat := <- inferior.Events() // eat notification that inferior got SIGSTOP
  status := stat.(syscall.WaitStatus)
  if !status.Stopped() {
    fmt.Printf("expected stop! program probably ended too quickly.\n")
    inferior.Close()
    return
  }
  // now that it's stopped, write the stuff that says it can run, for later.
  write_1()

  symbols, err := bfd.SymbolsProcess(inferior)
  if err != nil {
    panic(fmt.Errorf("could not read inferior's symbols: %v\n", err))
  }
  symmalloc := symbol("malloc", symbols)
  if symmalloc == nil { panic("no malloc?!") }

  for {
    err = wait_for_breakpoint(inferior, symmalloc.Address())
    if err == io.EOF {
      break
    } else if err != nil {
      fmt.Fprintf(os.Stderr, "application exited abnormally, giving up.\n")
      break;
    }
    fmt.Printf("[go] application malloc'd.\n")
/*  This is all broken.  We need to do read .eh_frame/.debug_frame and decode
    them.  Then we'll know when malloc actually ends, and we can set a
    breakpoint there and finally read the return value.
    The ABI says the return value should go in RAX.  The argument goes in RDI.
    // A malloc call is a 5 byte instruction.  So break when we're back.
    err = wait_for_breakpoint(inferior, symmalloc.Address()+5)
    if err == io.EOF {
      break
    } else if err != nil {
      panic(err)
    }
    // I *wish* that RAX had our malloc return value now.  But it looks like
    // the address+5 breakpoint above just got us into the call, whereas we
    // wanted to stop just after the call *returned*.  le sigh...
    regs, err := inferior.GetRegs()
    if err != nil { panic(err) }
    fmt.Printf("looking for retval at: 0x%x, or 0x%x\n", regs.Rbp-8, regs.Rax)
    ptr, err := inferior.ReadWord(uintptr(regs.Rbp-8))
    if err != nil {
      fmt.Fprintf(os.Stderr, "%v\n", err)
    } else {
      fmt.Printf("BACK from malloc.  retval was: 0x%x\n", ptr)
    }
*/
  }
  inferior.Close()
}
