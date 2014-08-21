// Houses the commands we use in our interactive debugging mode.
package main

import "bufio"
import "bytes"
import "debug/dwarf"
import "debug/elf"
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
  // cfg.FromAddress needs the entry point of the function.
  // Thus we need to identify where we are within the execution.
  symb, err := where(inferior)
  if err != nil { return err }

  graph := cfg.FromAddress(globals.program, symb.Address())
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
    fmt.Printf("0x%08x: %-25v | %-34s\n", addr, ixn, x86asm.IntelSyntax(ixn))

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

  graph := cfg.FromAddress(globals.program, symb.Address())
  if len(graph) == 0 {
    return fmt.Errorf("could not build local CFG for %s@0x%0x", symb.Name(),
                      symb.Address())
  }
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
    return nil, fmt.Errorf("no reasonable BBs out of %d", len(graph))
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
      return bad, 0x0, io.EOF // i.e. exited BB before hitting opcode.
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

func readmem(memref x86asm.Mem, inferior *ptrace.Tracee,
             signed bool) (int64, error) {
  regs, err := inferior.GetRegs()
  if err != nil {
    return 0, fmt.Errorf("could not read regs: %v", err)
  }
  var mr uintptr
  switch memref.Base {
  case x86asm.RIP: mr = uintptr(regs.Rip);
  case x86asm.RBP: mr = uintptr(regs.Rbp);
  }
  mr = uintptr(int64(mr) + int64(int32(memref.Disp)))
/*
  fmt.Printf("memref: seg: %v, base: %v, scale: %v, index: %v, disp: %d\n",
             memref.Segment, memref.Base, memref.Scale, memref.Index,
             int64(int32(memref.Disp)))
  fmt.Printf("0x%0x + %v == 0x%0x\n", regval, int64(int32(memref.Disp)), mr)
*/

  val, err := inferior.ReadWord(mr)
  if err != nil {
    return 0, fmt.Errorf("reading value @ 0x%0x: %v", mr, err)
  }
  if signed {
    fmt.Printf("mem pre-conversion, val is: %v(0x%0x)\n", val, val)
    val = endianconvert(val)
    fmt.Printf("mem post-conversion, val is: %v(0x%0x)\n", val, val)
  }
  return int64(val), nil
}

func readreg(regref x86asm.Reg, inferior *ptrace.Tracee,
             signed bool) (int64, error) {
  regs, err := inferior.GetRegs()
  if err != nil { return 0, err }

  var v uint64
  switch regref {
  case x86asm.RAX: v = regs.Rax
  case x86asm.RCX: v = regs.Rcx
  case x86asm.RDX: v = regs.Rdx
  case x86asm.RBX: v = regs.Rbx
  case x86asm.RSP: v = regs.Rsp
  case x86asm.RBP: v = regs.Rbp
  case x86asm.RSI: v = regs.Rsi
  case x86asm.RDI: v = regs.Rdi
  case x86asm.R8: v = regs.R8
  case x86asm.R9: v = regs.R9
  default: panic("unhandled case")
  }

  if signed {
    fmt.Printf("pre-conversion, regval is: %v(0x%0x)\n", v, v)
    v = endianconvert(v)
  }
  return int64(v), nil
}

// identify the bounds of the loop[s] of where we are now.
// note this will execute the inferior a little bit.
func bind_identify(fqn string, node *cfg.Node,
                   inferior *ptrace.Tracee) ([]uint, error) {
  dims := make([]uint, 0)
  for _, hdr := range node.Headers {
    if !hdr.LoopHeader() { panic("non-header in header list!") }
    // This whole approach needs overhauled.
    // We need to find the CMP instruction and run the inferior until then.
    // We also need to do some data flow analysis to identify the *source* of
    // both datums in the instruction.  We need to know the source so we can
    // look it up in the debug info and figure out its signedness.

    // This is a bit painful, since there's lots of different ways the compiler
    // can encode the loop header.  If you find a program is dying with an
    // io.EOF here, then the structure of your loop header is unknown and you
    // need to add a case here.
    ixn, mraddr, err := find_2regmem([]x86asm.Op{x86asm.MOV, x86asm.CMP},
                                     x86asm.RIP, hdr.Addr, inferior)
    if err == io.EOF { // no such instruction, let's go for a different case.
      fmt.Printf("searching for frame-relative memref in CMP instruction...\n")
      ixn, mraddr, err = find_2regmem([]x86asm.Op{x86asm.CMP}, x86asm.RBP,
                                      hdr.Addr, inferior)
    }
    if err != nil { return nil, err }

    // now wait until we hit that instruction, whatever it is.
    fmt.Printf("waiting until 0x%0x\n", mraddr)
    if err := debug.WaitUntil(inferior, mraddr) ; err != nil {
      return nil, err
    }

    memref := ixn.Args[1].(x86asm.Mem)
    // some checks to make sure the instruction is as we think...
    assert(memref.Base == x86asm.RIP || memref.Base == x86asm.RBP)
    if memref.Base == x86asm.RIP && memref.Disp < 0x100 {
      panic("displacement too small; makes no sense")
    }

    // this needs to be better.  we might be looking at a CMP instruction of
    // two registers, but the registers were loaded based on the frame pointer.
    // Thus we need to look at the data flow and see not just what the thing
    // being referenced is, but rather the source of its value.
    signed := false
    if memref.Base == x86asm.RBP {
      signed, err = dbg_parameter_signed(fqn, memref.Disp)
      if signed {
        fmt.Printf("memory value is signed, signing its read.")
      }
      if err != nil { return nil, err }
    }
    // before we read, make sure we're at the cmp instruction.
    if ixn.Op != x86asm.CMP {
      fmt.Printf("not quite at CMP.  stepping...\n")
      if err := inferior.SingleStep() ; err != nil {
        return nil, err
      }
    }

    memarg, err := readmem(memref, inferior, signed)
    if err != nil { return nil, err }

    // fixme: figure out if the reg argument is signed (need DFlow analysis)
    regarg, err := readreg(ixn.Args[0].(x86asm.Reg), inferior, false)
    if err != nil { return nil, err }
    fmt.Printf("reg, mem: %v, %v\n", regarg, memarg)

    larger := regarg
    if memarg > regarg { larger = memarg }

    dims = append(dims, uint(larger))

    subdims, err := bind_identify(fqn, hdr, inferior)
    if err != nil { return nil, err }
    for _, x := range subdims {
      dims = append(dims, x)
    }
  }
  return dims, nil
}

// finds the given function in the list of those that dwarf gives.
func dbg_function(symname string, rdr *dwarf.Reader) (*dwarf.Entry, error) {
  for ent, err := rdr.Next(); ent != nil && err != io.EOF;
      ent, err = rdr.Next() {
    if err != nil { return nil, err }
    if ent.Tag == dwarf.TagSubprogram {
      for _, fld := range ent.Field {
        if fld.Attr == dwarf.AttrName && fld.Val.(string) == symname {
          return ent, nil
        } else if fld.Attr == dwarf.AttrName {
          // minor optimization: if it's a subprogram but not the one we're
          // looking for, skip all its local variables and the like.
          rdr.SkipChildren()
        }
      }
    }
  }
  return nil, io.EOF
}
// reads the type from the given dwarf debug symbol
func dbg_type(flds []dwarf.Field) (dwarf.CommonType, error) {
  for _, fld := range flds {
    if fld.Attr == dwarf.AttrType {
      return fld.Val.(dwarf.CommonType), nil
    }
  }
  return dwarf.CommonType{}, fmt.Errorf("no type found")
}

// converts a signed "LEB128" from a byte array into a signed integer.
// algorithm is modified from the dwarf v4 spec.
func sleb128(leb []uint8) int64 {
  result := uint64(0) // go forces unsigned for shifting.  cast later.  sigh.
  shift := uint(0)
  const nbits = 64
  for b := range leb {
    // 0x91 seems to indicate 'this is a multi-byte thing' as opposed to
    // actually being used.  Not 100% sure this is correct, but we match
    // objdump on some test code with this continue.
    if leb[b] == 0x91 { continue }
    value := leb[b] & 0x7f
    result |= uint64(value) << uint64(shift)
    shift += 7
    // the DWARF algorithm reads the high-order bit as a sentinel, but instead
    // of an infinite array the Go API just gives us a correctly-sized slice.
  }
  // highest-order bit is the sentinel, so second highest is the sign.
  if shift < nbits && (leb[len(leb)-1] & 0x40) != 0 {
    result = result | uint64(int64(-1) << shift) // sign extension.
  }
  return int64(result)
}

func dbg_parameter_signed(fqnname string, offset int64) (bool, error) {
  legolas, err := elf.Open(globals.program)
  if err != nil { return false, err }
  defer legolas.Close()

  gimli, err := legolas.DWARF()
  if err != nil { return false, err }

  typ, err := dbg_parameter_type(fqnname, gimli, offset)
  if err != nil { return false, err }
  switch(typ.Name) {
  case "float", "double", "int8_t", "int16_t", "int32_t", "int64_t":
    return true, nil
  case "size_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t":
    return false, nil
  default: return false, fmt.Errorf("unknown type: '%v'\n", typ.Common().Name)
  }
}

func print_type(entry *dwarf.Entry, rdr *dwarf.Reader) {
  atype, ok := entry.Val(dwarf.AttrType).(dwarf.Offset)
  if !ok { return }
  rdr.Seek(atype)
  ent, err := rdr.Next()
  if err != nil { panic(err) }

  fmt.Printf("type: %v\n", ent)
  for _, f := range ent.Field {
    fmt.Printf("\t %v\n", f)
  }
  print_type(ent, rdr)
}

// given a type, follows the type chain until it gets to the base type and then
// returns its name.
func dbg_base_type(entry *dwarf.Entry) (*dwarf.Entry, error) {
  bad := &dwarf.Entry{}
  legolas, err := elf.Open(globals.program)
  if err != nil { return bad, err }
  defer legolas.Close()
  gimli, err := legolas.DWARF()
  if err != nil { return bad, err }

  atype, ok := entry.Val(dwarf.AttrType).(dwarf.Offset)
  if !ok { return bad, fmt.Errorf("bad entry point") }
  rdr := gimli.Reader()
  rdr.Seek(atype)
  ent, err := rdr.Next()
  if err != nil { return bad, err }

  if ent.Tag == dwarf.TagBaseType {
    _, ok := ent.Val(dwarf.AttrName).(string)
    if !ok { return bad, fmt.Errorf("name is not a string?") }
    return ent, nil
  }
  return dbg_base_type(ent) // recurse.
}


// 'param' is given as an offset off of the frame pointer.
func dbg_parameter_type(fqn string, dwf *dwarf.Data,
                        offset int64) (dwarf.CommonType, error) {
  // seems to be broken somehow, always returning a blank type....
  bad := dwarf.CommonType{}
  rdr := dwf.Reader()
  entry, err := dbg_function(fqn, rdr)
  if err != nil { return bad, err }
  if !entry.Children {
    return bad, fmt.Errorf("function %v has no children?", entry)
  }

  for ent, err := rdr.Next(); ent != nil && ent.Tag != 0 && err != io.EOF;
      ent, err = rdr.Next() {
    if ent.Tag == dwarf.TagFormalParameter {
      val, ok := ent.Val(dwarf.AttrLocation).([]uint8)
      if !ok {
        return bad, fmt.Errorf("location is not a byte array")
      }
      leb := sleb128(val)
      if leb == offset {
        ty, err := dbg_base_type(ent)
        if err != nil { return bad, err }
        if ty.Tag != dwarf.TagBaseType { panic("dbg_base_type is buggy") }
        typ, err := dwf.Type(ty.Offset)
        if err != nil { return bad, err }
        return *typ.Common(), nil
      }
    }
  }

  return bad, fmt.Errorf("offset never found")
}

type cdebuginfo struct {
  fqn string
  offset string
}
func (c cdebuginfo) Execute(inferior *ptrace.Tracee) error {
  // parse 'c.offset' into a usable number instead of a string.
  var offset int64
  if c.offset == "" { // the parameter is optional.
    offset = 0
  } else {
    var err error
    offset, err = strconv.ParseInt(c.offset, 0, 64)
    if err != nil {
      return fmt.Errorf("cannot convert %v to an offset: %v\n", c.offset, err)
    }
  }

  if err := verify_symbols_loaded(inferior) ; err != nil {
    return err
  }
  sym := symbol(c.fqn, symbols)
  if sym == nil {
    return fmt.Errorf("could not find '%s' among the %d known symbols.",
                      c.fqn, len(symbols))
  }
  legolas, err := elf.Open(globals.program)
  if err != nil { return err }
  defer legolas.Close()

  gimli, err := legolas.DWARF()
  if err != nil { return err }

  rdr := gimli.Reader()
  fqn, err := dbg_function(c.fqn, rdr)
  if err != nil { return err }
  fmt.Printf("ent: %v\n", fqn)

  if offset == 0 {
    return nil
  }
  typ, err := dbg_parameter_type(c.fqn, gimli, offset)
  if err != nil { return err }
  fmt.Printf("type: %v\n", typ)

  return nil
}

// identifies the loop bounds for all headers which bound the current location.
type cbounds struct{}
func (cbounds) Execute(inferior *ptrace.Tracee) error {
  symb, err := where(inferior)
  if err != nil { return err }

  graph := cfg.FromAddress(globals.program, symb.Address())
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

  graph := cfg.FromAddress(globals.program, symb.Address())
  if err != nil { return err }
  if rn := root_node(graph, symb) ; rn != nil {
    cfg.Analyze(rn)
  }

  bb, err := basic_block(graph, whereis(inferior))
  if err != nil { return err }

  dims, err := bind_identify(symb.Name(), bb, inferior)
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
    case "debuginfo":
      if len(tokens) == 3 { return cdebuginfo{tokens[1], tokens[2]} }
      if len(tokens) == 2 { return cdebuginfo{tokens[1], ""} }
      return cparseerror{"invalid # of arguments."}
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
