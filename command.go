// Houses the commands we use in our interactive debugging mode.
package main

import "bufio"
import "errors"
import "fmt"
import "io"
import "os"
import "sort"
import "strconv"
import "strings"
import "syscall"
import "github.com/tfogal/ptrace"
import "code.google.com/p/rsc.x86/x86asm"
import "./bfd"
import "./cfg"
import "./debug"

type CmdGlobal struct {
  program string
}

// the list of symbols from the process, might be nil.
var symbols []bfd.Symbol
// initialization info that commands might want to use.
var globals CmdGlobal

func verify_symbols_loaded(inferior *ptrace.Tracee) error {
  if symbols == nil {
    var err error // so we can use "=" and ensure 'symbols' is the global.
    symbols, err = bfd.SymbolsProcess(inferior)
    if err != nil { return err }
  }
  return nil
}

type Command interface{
  Execute(*ptrace.Tracee) (error)
}

type cgeneric struct {
  args []string
}
func (c cgeneric) Execute(proc *ptrace.Tracee) (error) {
  fmt.Printf("unknown cmd: %s\n", c.args)
  return nil
}

type ccontinue struct {
  args []string
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
    case 'D': fmt.Printf("in uninterruptible sleep (io?)\n"); break
    case 'R': fmt.Printf("running\n"); break
    case 'S': fmt.Printf("sleeping\n"); break
    case 't': fmt.Printf("stopped (tracing)\n"); break
    case 'W': fmt.Printf("(impossibly) paging\n"); break
    case 'X': fmt.Printf("(impossibly) dead\n"); break
    case 'Z': fmt.Printf("awaiting reaping.\n"); break
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

type cwait struct{
  funcname string
}
func (c cwait) Execute(inferior *ptrace.Tracee) (error) {
  if err := verify_symbols_loaded(inferior) ; err != nil {
    return err
  }
  // they can give either an address or the name of an actual function.
  address := uintptr(0x0)
  if len(c.funcname) > 2 && c.funcname[0:2] == "0x" {
    saddr, err := strconv.ParseInt(c.funcname, 0, 64)
    if err != nil { return err }
    if saddr < 0 { panic("address cannot be negative, that makes no sense.") }
    address = uintptr(saddr)
  } else {
    sym := symbol(c.funcname, symbols) // symbol lookup
    if sym == nil {
      return fmt.Errorf("could not find '%s' among the %d known symbols.",
                        c.funcname, len(symbols))
    }
    address = sym.Address()
  }
  err := debug.WaitUntil(inferior, address)
  if err == io.EOF {
    fmt.Printf("Program ended before '%s' was hit.\n", c.funcname)
    return nil
  }
  if err != nil { return err }
  return nil
}

type cparseerror struct{
  reason string
}
func (c cparseerror) Execute(*ptrace.Tracee) (error) {
  return fmt.Errorf("parse error: %s", c.reason)
}

type cregisters struct{}
func (cregisters) Execute(inferior *ptrace.Tracee) (error) {
  regs, err := inferior.GetRegs()
  if err != nil { return err }

  wd, err := inferior.ReadWord(uintptr(regs.Rip))
  if err != nil { return err }

  fmt.Printf("%9s %14s %14s %13s %21s\n", "iptr", "RAX", "RBP", "RSP",
             "next-opcode")
  fmt.Printf("0x%012x 0x%012x 0x%012x 0x%012x 0x%012x\n", regs.Rip, regs.Rax,
             regs.Rbp, regs.Rsp, wd)
  return nil
}

type csymbol struct{
  symname string
}
func (c csymbol) Execute(inferior *ptrace.Tracee) (error) {
  if err := verify_symbols_loaded(inferior) ; err != nil {
    return err
  }
  sym := symbol(c.symname, symbols) // symbol lookup
  if sym == nil {
    return fmt.Errorf("could not find '%s' among the %d known symbols.",
                      c.symname, len(symbols))
  }
  fmt.Printf("'%s' is at 0x%012x\n", sym.Name(), sym.Address())
  return nil
}

type cderef struct {
  addr string // really, a uintptr, but do the parsing in the command.
}
func (c cderef) Execute(inferior *ptrace.Tracee) (error) {
  if c.addr == "" {
    return errors.New("empty address given")
  }
  ui, err := strconv.ParseUint(c.addr, 0, 64)
  if err != nil { return err }
  address := uintptr(ui)

  fmt.Printf("addr: 0x%0x\n", address)

  word, err := inferior.ReadWord(address)
  if err != nil { return err }

  fmt.Printf("0x%0x\n", word)
  return nil
}

// need these to be able to sort symbols on addresses.
type SymListA []bfd.Symbol
func (s SymListA) Len() int { return len(s) }
func (s SymListA) Less(i int, j int) bool {
	return s[i].Address() < s[j].Address()
}
func (s SymListA) Swap(i int, j int) { s[i], s[j] = s[j], s[i] }

// find what function the given address is in.
func find_function(address uintptr) (*bfd.Symbol, error) {
  if len(symbols) == 0 {
    return nil, errors.New("symbol list is empty, forgot to load them?")
  }
  // copy our symlist to a new variable so that we can change the sort order to
  // be addresses instead of names without mucking up our normal table.
  addr_syms := make([]bfd.Symbol, len(symbols))
  copy(addr_syms, symbols)
  sort.Sort(SymListA(addr_syms))

  // We can't use sort.Search here because 'address' can be in the middle of a
  // function, and we don't have an entry for every possible address.  We just
  // want to find the "minimum" address we are in.
  fidx := 0
  for i, sy := range addr_syms { // todo we should really do a binary search
    if sy.Address() <= address { fidx = i }
    if sy.Address() > address { break } // will never find anything
  }
  if fidx == len(addr_syms) {
    return nil, fmt.Errorf("addr 0x%0x not found in %d-symbol list", address,
                           len(addr_syms))
  }
  if addr_syms[fidx].Address() == 0x0 {
    return nil,
           errors.New("we are near NULL?  I don't believe it, probably a bug.")
  }
  if addr_syms[fidx].Name() == "" {
    return nil, errors.New("insn ptr is in no man's land.")
  }
  return &addr_syms[fidx], nil
}

// identifies the root node (function entry point) of the graph
func root_node(graph map[uintptr]*cfg.Node, symb *bfd.Symbol) *cfg.Node {
  for _, v := range graph {
    if v.Name == symb.Name() || v.Addr == symb.Address() { return v }
  }
  return nil
}

// build CFG for local function
type ccfg struct {
  filename string // output to this file, if set.
}
func (c ccfg) Execute(inferior *ptrace.Tracee) (error) {
  // cfg.Local does its filtering based on the symbol (really, function) name.
  // Thus we need to identify where we are within the execution.
  symb, err := where(inferior)
  if err != nil { return err }

  graph := cfg.Local(globals.program, symb.Name())
  // sometimes it seems we are unable to find the root node.  this appears to
  // only happen if the function lives in a stripped shared library.
  if rn := root_node(graph, symb) ; rn != nil {
    cfg.Analyze(rn)
    // output to a file that defaults to stdout.  But 'inorder' needs a
    // 1-argument function, so construct a closure around the appropriate
    // writer.
    writer := os.Stdout
    if c.filename != "" {
      writer, err = os.OpenFile(c.filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
                                0666)
      if err != nil { return err }
    }
    printer := func(node *cfg.Node) { dotNode(node, writer) }
    fmt.Fprintf(writer, "digraph %s {\n", symb.Name())
    fmt.Fprintf(writer, "\tranksep=\"0.2 equally\";\n\tratio=0.7;\n")
    inorder(graph, printer)
    fmt.Fprintf(writer, "}\n")
    if writer != os.Stdout {
      if err := writer.Close() ; err != nil {
        return err
      }
      fmt.Printf("Output '%s' successfully created.\n", c.filename)
    }
  } else {
    fmt.Printf("Cannot find root node of %d-element graph!\n", len(graph))
    fmt.Printf("This likely means the function is in a stripped shared ")
    fmt.Printf("library.  Build the library with debug symbols and do not ")
    fmt.Printf("strip it if you'd like to be able to generate this CFG.\n")
  }
  return nil
}

// print out the list of known symbols.
type csymlist struct{}
func (csymlist) Execute(inferior *ptrace.Tracee) (error) {
  if err := verify_symbols_loaded(inferior) ; err != nil { return err }

  n := 0
  for _, s := range symbols {
    if n+1+len(s.Name()) > 80 {
      fmt.Printf("\n")
      n = 0
    }
    if s.Name() == "" { continue } // stupid "blank" symbols, WTF are these??
    nbytes, err := fmt.Printf("%s ", s.Name())
    if err != nil { return err }

    n += nbytes
  }
  fmt.Printf("\n")
  return nil
}

// identifies the function the inferior is currently located in.
func where(inferior *ptrace.Tracee) (*bfd.Symbol, error) {
  if err := verify_symbols_loaded(inferior) ; err != nil { return nil, err }
  regs, err := inferior.GetRegs()
  if err != nil { return nil, err }

  symbol, err := find_function(uintptr(regs.Rip))
  if err != nil { return nil, err }
  return symbol, nil
}

// maps the current instruction pointer to a function and then tells the user
// where they are.
type cwhereami struct{}
func (cwhereami) Execute(inferior *ptrace.Tracee) (error) {
  symb, err := where(inferior)
  if err != nil { return err }
  iptr, err := inferior.GetIPtr()
  if err != nil { return err }

  diff := iptr - symb.Address()
  fmt.Printf("0x%012x  %s+%d\n", iptr, symb.Name(), diff)
  return nil
}

// decodes the instruction[s] for the given loop header basic block.
type cdecode struct{
  addr string
}
func (c cdecode) Execute(inferior *ptrace.Tracee) error {
  address := uintptr(0x0)
  // accept "%reg" to mean 'grab the address of from the given register"
  if strings.Contains(c.addr, "%") { // register reference.
    regs, err := inferior.GetRegs()
    if err != nil { return err }
    switch(c.addr) {
    case "%rip": address = uintptr(regs.Rip)
    case "%rbp": address = uintptr(regs.Rbp)
    case "%rsp": address = uintptr(regs.Rsp)
    default: return fmt.Errorf("reg '%s' unknown.", c.addr)
    }
  } else {
    ui, err := strconv.ParseUint(c.addr, 0, 64)
    if err != nil { return err }
    address = uintptr(ui)
  }

  // max length of an instruction in x86-64 is 16 bytes (unconfirmed..).
  insn := make([]byte, 16)
  if err := inferior.Read(address, insn) ; err != nil { return err }

  ixn, err := x86asm.Decode(insn, 64)
  if err != nil { return err }
  fmt.Printf("insn: %v\n", ixn)

  return nil
}

// finds the basic block that the given address is part of
func
basic_block(graph map[uintptr]*cfg.Node, address uintptr) (*cfg.Node, error) {
  closest_addr := uintptr(0x0)
  closest := (*cfg.Node)(nil)
  for addr, node := range graph {
    if addr <= address && addr > closest_addr {
      closest_addr = addr
      closest = node
    }
  }
  if closest == nil {
    return nil, fmt.Errorf("could not find any reasonable basic blocks.")
  }
  return closest, nil
}

func print_bindlist(node *cfg.Node) {
  for _, hdr := range node.Headers {
    fmt.Printf("0x%0x is bound by (%s, 0x%0x)\n", node.Addr, hdr.Name, hdr.Addr)
    print_bindlist(hdr)
  }
}
// identifies the loop bounds for all headers which bound the current location.
type cbounds struct{}
func (cbounds) Execute(inferior *ptrace.Tracee) error {
  symb, err := where(inferior)
  if err != nil { return err }

  graph := cfg.Local(globals.program, symb.Name())
  if err != nil { return err }
  if rn := root_node(graph, symb) ; rn != nil {
    cfg.Analyze(rn)
  }

  bb, err := basic_block(graph, whereis(inferior))
  if err != nil { return err }
  fmt.Printf("closest bb to 0x%0x is (%s, 0x%0x)\n", whereis(inferior),
             bb.Name, bb.Addr)
  print_bindlist(bb)

  return nil
}

func parse_cmdline(line string) (Command) {
  tokens := strings.Split(line, " ")
  if len(tokens) == 0 { return cparseerror{"no tokens"} }
  switch(tokens[0]) {
    case "cont": fallthrough
    case "continue": return ccontinue{tokens[1:len(tokens)]}
    case "pid": return cpid{}
    case "quit": fallthrough
    case "exit": return cquit{}
    case "stat": fallthrough
    case "status": return cstatus{}
    case "stepi": fallthrough
    case "step": return cstep{}
    case "break": return cstop{} // opposite of 'continue' :-)
    case "wait":
      if len(tokens) == 1 { return cparseerror{"not enough arguments"} }
      return cwait{tokens[1]}
    case "regs": fallthrough
    case "registers": return cregisters{}
    case "sym": fallthrough
    case "symbol":
      if len(tokens) == 1 { return cparseerror{"not enough arguments"} }
      return csymbol{tokens[1]}
    case "deref":
      if len(tokens) == 1 { return cparseerror{"not enough arguments"} }
      return cderef{tokens[1]}
    case "cfg":
      if len(tokens) == 1 { return ccfg{} }
      if len(tokens) == 2 { return ccfg{tokens[1]} } // 1, optional, parameter.
      return cparseerror{"too many arguments"}
    case "symlist": fallthrough
    case "symbols": return csymlist{}
    case "whereami": return cwhereami{}
    case "decode":
      if len(tokens) != 2 { return cparseerror{"not enough arguments"} }
      return cdecode{tokens[1]}
    case "bounds": return cbounds{}
    default: return cgeneric{tokens}
  }
}
func Commands(gbl CmdGlobal) (chan Command) {
  globals = gbl
  cmds := make(chan Command)
  go func() {
    defer close(cmds)
    rdr := bufio.NewReader(os.Stdin)
    for {
      <- cmds // wait for 'green light' from our parent.
      fmt.Printf("> ")
      os.Stdout.Sync()
      s, err := rdr.ReadString('\n')
      if err != nil {
        fmt.Fprintf(os.Stderr, "error scanning line: %v\n", err)
        cmds <- nil // signal EOF.
        return
      }
      cmd := parse_cmdline(strings.TrimSpace(s))
      cmds <- cmd
    }
  }()
  return cmds
}
