// Houses the commands we use in our interactive debugging mode.
package main

import "bufio"
import "bytes"
import "encoding/binary"
import "errors"
import "fmt"
import "io"
import "os"
import "os/exec"
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
  // they can give us either an address or the name of an actual function.
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

type cregisters struct{
  regname string
}
func (c cregisters) Execute(inferior *ptrace.Tracee) (error) {
  regs, err := inferior.GetRegs()
  if err != nil { return err }

  wd, err := inferior.ReadWord(uintptr(regs.Rip))
  if err != nil { return err }

  switch c.regname {
  case "":
    fmt.Printf("%9s %14s %14s %13s %21s\n", "iptr", "RAX", "RBP", "RSP",
               "next-opcode")
    fmt.Printf("0x%012x 0x%012x 0x%012x 0x%012x 0x%012x\n", regs.Rip, regs.Rax,
               regs.Rbp, regs.Rsp, wd)
  case "rax": fmt.Printf("0x%012x\n", regs.Rax)
  case "rbx": fmt.Printf("0x%012x\n", regs.Rbx)
  case "rcx": fmt.Printf("0x%012x\n", regs.Rcx)
  case "rdx": fmt.Printf("0x%012x\n", regs.Rdx)
  case "rdi": fmt.Printf("0x%012x\n", regs.Rdi)
  case "rsi": fmt.Printf("0x%012x\n", regs.Rsi)
  case "r8": fmt.Printf("0x%012x\n", regs.R8)
  case "r9": fmt.Printf("0x%012x\n", regs.R9)
  case "r10": fmt.Printf("0x%012x\n", regs.R10)
  case "r11": fmt.Printf("0x%012x\n", regs.R11)
  case "r12": fmt.Printf("0x%012x\n", regs.R12)
  case "r13": fmt.Printf("0x%012x\n", regs.R13)
  case "r14": fmt.Printf("0x%012x\n", regs.R14)
  case "r15": fmt.Printf("0x%012x\n", regs.R15)
  }
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

func viewcfg(filename string) {
  cmd := exec.Command("viewcfg", filename)
  cmd.Start()
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
      viewcfg(c.filename)
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

func conditional_jump(ixn x86asm.Inst) bool {
  return ixn.Op == x86asm.JA || ixn.Op == x86asm.JAE || ixn.Op == x86asm.JB ||
         ixn.Op == x86asm.JBE || ixn.Op == x86asm.JCXZ ||
         ixn.Op == x86asm.JE || ixn.Op == x86asm.JECXZ || ixn.Op == x86asm.JG ||
         ixn.Op == x86asm.JGE || ixn.Op == x86asm.JL || ixn.Op == x86asm.JLE ||
         ixn.Op == x86asm.JNE || ixn.Op == x86asm.JNO || ixn.Op == x86asm.JNP ||
         ixn.Op == x86asm.JNS || ixn.Op == x86asm.JO || ixn.Op == x86asm.JP ||
         ixn.Op == x86asm.JRCXZ || ixn.Op == x86asm.JS;
}

// prints out the assembly starting at a given node, until we hit a
// conditional jump.
func disassemble_cond(inferior *ptrace.Tracee, node *cfg.Node) error {
  addr := node.Addr
  insn := make([]byte, 16) // max length of x86-64 insn is 16 bytes.

  // run through the block until we find a conditional jump, disassembling each
  // instruction as we go.  this is complicated slightly by unconditional
  // jumps: we need to be sure to follow them.
  for {
    if err := inferior.Read(addr, insn) ; err != nil { return err }

    ixn, err := x86asm.Decode(insn, 64)
    if err != nil { return err }
    fmt.Printf("0x%08x: \t%v\n", addr, ixn)

    if conditional_jump(ixn) { // jump instruction.  basic block is done.
      break
    }
    addr += uintptr(ixn.Len)
    if ixn.Op == x86asm.JMP { // also follow jumps!
      fmt.Printf("jmp!  args: %v\n", ixn.Args[0])
      addr += uintptr(ixn.Args[0].(x86asm.Rel))
    }
  }
  return nil
}

type cdisassemble struct{}
func (cdisassemble) Execute(inferior *ptrace.Tracee) error {
  symb, err := where(inferior)
  if err != nil { return err }

  graph := cfg.Local(globals.program, symb.Name())
  if err != nil { return err }
  if rn := root_node(graph, symb) ; rn != nil {
    cfg.Analyze(rn)
  }

  bb, err := basic_block(graph, whereis(inferior))
  if err != nil { return err }

  disassemble_cond(inferior, bb)
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

func print_bindlist(node *cfg.Node, inferior *ptrace.Tracee) {
  for _, hdr := range node.Headers {
    fmt.Printf("0x%08x", node.Addr)
    if node.LoopHeader() {
      fmt.Printf(",LH(%d)", node.Depth())
    } else {
      fmt.Printf("      ") // just keep it evenly spaced.
    }
    fmt.Printf(" is bound by 0x%0x", hdr.Addr)
    if hdr.LoopHeader() { fmt.Printf(",LHd(%d)", hdr.Depth()) }
    fmt.Printf("\n")
    if hdr.LoopHeader() {
      disassemble_cond(inferior, hdr)
    }
    print_bindlist(hdr, inferior)
  }
}

// x86asm.Args is always 4 elements, regardless of how many arguments the
// instruction takes.  if it takes fewer than 4, the 'extra' arguments will be
// nil.
func nargs(args x86asm.Args) uint {
  n := uint(0)
  for _, a := range args {
    if a != nil { n++ }
  }
  return n
}

func opcode_in(opcode x86asm.Op, ops []x86asm.Op) bool {
  for _, o := range ops {
    if o == opcode {
      return true
    }
  }
  return false
}

// starting from 'startaddr', find the next instruction which has the given
// opcode and 2 arguments, the first of which is the register given by 'reg'
// and the latter a memory reference.
// This will error out if it hits a conditional jump: start it from the basic
// block you care about.
func find_2regmem(opcodes []x86asm.Op, reg x86asm.Reg, startaddr uintptr,
                  inferior *ptrace.Tracee) (x86asm.Inst, uintptr, error) {
  insn := make([]byte, 16)
  addr := startaddr
  bad := x86asm.Inst{} // just a constant to return on error.
  for {
    if err := inferior.Read(addr, insn) ; err != nil { return bad, 0x0, err }

    ixn, err := x86asm.Decode(insn, 64)
    if err != nil { return bad, 0x0, err }

    if conditional_jump(ixn) {
      return bad, 0x0, errors.New("exited basic block before hitting opcode!")
    }

    if opcode_in(ixn.Op, opcodes) && nargs(ixn.Args) == 2 {
      _, isreg := ixn.Args[0].(x86asm.Reg)
      memref, ismem := ixn.Args[1].(x86asm.Mem)
      if isreg && ismem && memref.Base == reg {
        return ixn, addr, nil
      }
    }

    addr += uintptr(ixn.Len)
    if ixn.Op == x86asm.JMP {
      addr += uintptr(ixn.Args[0].(x86asm.Rel))
    }
  }
  return bad, 0x0, errors.New("inconceivable!") // not reachable.
}

// this is garbage.  we shouldn't need to hardcode this in.
func endianconvert(u uint64) uint64 {
  buf := bytes.NewBuffer(make([]byte, 0))
  binary.Write(buf, binary.BigEndian, u)
  bts := buf.Bytes()
  val := uint64(0)
  for i:=uint(0); i < uint(len(bts)) ; i++ {
    val |= uint64(bts[i]) << i
  }
  return val
}

// identify the bounds of the loop[s] of where we are now.
// note this will execute the inferior a little bit.
func bind_identify(node *cfg.Node, inferior *ptrace.Tracee) ([]uint, error) {
  dims := make([]uint, 0)
  for _, hdr := range node.Headers {
    if !hdr.LoopHeader() { panic("non-header in header list!") }
    if hdr.LoopHeader() {
      ixn, mraddr, err := find_2regmem([]x86asm.Op{x86asm.MOV, x86asm.CMP},
                                       x86asm.RIP, hdr.Addr, inferior)
      if err != nil { return nil, err }
      memref := ixn.Args[1].(x86asm.Mem)
      if memref.Base != x86asm.RIP { panic("found wrong insn") }
      if memref.Disp < 0x10 { panic("displacement makes no sense") }

/*
      fmt.Printf("memref info:\n\tseg: %v\n\tbase: %v\n\tscale: %v\n",
                 memref.Segment, memref.Base, memref.Scale)
      fmt.Printf("\tindex: %v\n\tdisp: 0x%0x\n", memref.Index, memref.Disp)
*/
      // now wait until we hit that instruction, whatever it is.
      if err := debug.WaitUntil(inferior, mraddr) ; err != nil {
        return nil, err
      }

      // now that we're here, we can compute the memory reference address and
      // read the value we are looking for.
      regs, err := inferior.GetRegs()
      if err != nil { return nil, err }
      mr := uintptr(regs.Rip) + uintptr(memref.Disp)
      // this is bad news if the variable is not 64bits wide...
      val, err := inferior.ReadWord(mr)
      if err != nil { return nil, err }
      val = endianconvert(val) // why do we need this?!

      dims = append(dims, uint(val))
    }
    subdims, err := bind_identify(hdr, inferior)
    if err != nil { return nil, err }
    for _, x := range subdims {
      dims = append(dims, x)
    }
  }
  return dims, nil
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
  print_bindlist(bb, inferior)

  return nil
}

// identify loop bounds.  assumes we are inside a series of nested loops.  will
// execute the inferior some to identify these loops.
type cboundid struct{}
func (cboundid) Execute(inferior *ptrace.Tracee) error {
  symb, err := where(inferior)
  if err != nil { return err }

  graph := cfg.Local(globals.program, symb.Name())
  if err != nil { return err }
  if rn := root_node(graph, symb) ; rn != nil {
    cfg.Analyze(rn)
  }

  bb, err := basic_block(graph, whereis(inferior))
  if err != nil { return err }

  dims, err := bind_identify(bb, inferior)
  if err != nil { return err }
  if len(dims) == 0 {
    if len(bb.Headers) != 0 { panic("broken Headers definition ?") }
    return errors.New("not currently in a loop.")
  }
  fmt.Printf("dims: %v\n", dims)
  return nil
}

// reads from memory at the given location and prints it out.
type cread struct{
  location string
}
func (c cread) Execute(inferior *ptrace.Tracee) error {
  ui, err := strconv.ParseUint(c.location, 0, 64)
  if err != nil { return err }
  address := uintptr(ui)

  word, err := inferior.ReadWord(address)
  if err != nil { return err }

  fmt.Printf("0x%08x\n", word)
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
    case "registers":
      if len(tokens) == 2 { return cregisters{tokens[1]} }
      return cregisters{""}
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
    case "disassemble": return cdisassemble{}
    case "read":
      if len(tokens) == 1 { return cparseerror{"not enough arguments"} }
      return cread{tokens[1]}
    case "boundid": return cboundid{}
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
