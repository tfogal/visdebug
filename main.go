package main

import(
  "bufio"
  "bytes"
  "encoding/binary"
  "errors"
  "flag"
  "fmt"
  "io"
  "os"
  "log"
  "reflect"
  "runtime"
  "runtime/pprof"
  "strings"
  "syscall"
  "unsafe"
  "github.com/tfogal/ptrace"
  "code.google.com/p/rsc.x86/x86asm"
  "./bfd"
  "./cfg"
  "./debug"
  "./gfx"
  "./msg"
)

// for information regarding code injection
var inject = msg.StdChan()
// progress / status of what's going on with memory protection.
var protection = msg.StdChan()

func procstatus(pid int, stat syscall.WaitStatus) {
  if stat.CoreDump() { log.Fatalf("core dumped"); }
  if stat.Continued() { fmt.Printf("continued\n"); }
  if stat.Exited() {
    fmt.Printf("exited with status: %d\n", stat.ExitStatus())
  }
  if stat.Signaled() {
    log.Fatalf("unexpected signal %v\n", stat.Signal())
  }
  if stat.Stopped() {
    fmt.Printf("stopped with signal: %v\n", stat.StopSignal())
  }
  fmt.Printf("PID %d trap cause: %d\n", pid, stat.TrapCause())
}

func readsymbols(filename string) {
  symbols, err := bfd.Symbols(filename)
  if err != nil { log.Fatalf(err.Error()) }

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
    if(symbol.Debug()) { flags += "DBG " } else { flags += "    " }
    if(symbol.Function()) { flags += "FQN " } else { flags += "    " }
    if(symbol.Weak()) { flags += "WEAK " } else { flags += "     " }
    if(symbol.Indirect()) { flags += "IND " } else { flags += "    " }
    if(symbol.Dynamic()) { flags += "DYN " } else { flags += "    " }
    if(symbol.IndirectFunction()) { flags += "IFQN " } else { flags += "     " }
    fmt.Printf("%s %s\n", flags, symbol.Name());
  }
}

func assert(condition bool) {
  if condition == false {
    os.Stdout.Sync()
    panic("assertion failure")
  }
}

var symlist bool
var execute bool
var dotcfg bool
var dyninfo bool
var freespace bool
var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
var malloctrace bool
var memhandle bool
var vis2d bool
var minsize uint
var null bool
func init() {
  runtime.LockOSThread()
  flag.BoolVar(&symlist, "symbols", false, "print out the symbol table")
  flag.BoolVar(&symlist, "s", false, "print out the symbol table")
  flag.BoolVar(&execute, "x", false, "execute subprogram")
  flag.BoolVar(&dotcfg, "cfg", false, "compute and print CFG")
  flag.BoolVar(&dyninfo, "attach", false, "attach and print dynamic info")
  flag.BoolVar(&freespace, "free", false, "show maps and find first free space")
  flag.BoolVar(&malloctrace, "mt", false, "trace 'malloc' calls")
  flag.BoolVar(&memhandle, "dbg", false, "instrument, adding checks for " +
                                         "invalid memory handling")
  flag.BoolVar(&vis2d, "v2d", false, "visualize 2D data")
  flag.UintVar(&minsize, "size", 0, "allocation size to threshold")
  flag.BoolVar(&null, "null", false, "use null malloc tracer")
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

  log.SetFlags(log.Lshortfile)

  if *cpuprofile != "" {
    f, err := os.Create(*cpuprofile)
    if err != nil { panic(err) }
    pprof.StartCPUProfile(f)
    defer pprof.StopCPUProfile()
  }

  // we're not running anything yet, and might not ever depending on the option
  // given, so we need to leave symbols nil and fill it in later.
  globals = CmdGlobal{program: argv[0], symbols: nil, minsize: minsize}

  if symlist {
    readsymbols(argv[0]);
  }

  if(dotcfg) {
    graph := cfg.Build(argv[0])
    root := findNodeByName(graph, "main")
    if root == nil { panic("CFG broken?  no 'main' node") }
    cfg.Analyze(root)
    fmt.Printf("digraph %s {\n", basename(argv[0]))
    printer := func(node *cfg.Node) { dotNode(node, os.Stdout) }
    inorder(graph, printer)
    fmt.Println("}");
  }

  if execute {
    interactive(argv)
  }
  if malloctrace {
    var mt MallocTrace
    supervise(argv, &mt)
  }
  if null {
    var n Null
    supervise(argv, &n)
  }
  if vis2d {
    var vmem visualmem2D
    go func() { // gfx stuff needs to go into another thread.
      if err := gfx.Context() ; err != nil { // establish OGL stuff.
        evc.Trace("Could not establish context: %v, skipping..\n", err)
        gfx.Close()
        return
      }
      supervise(argv, &vmem)
      gfx.Close()
    }()
    gfx.Main()
  }

  if memhandle {
    var aa AlignAlloc
    supervise(argv, &aa)
  }
  if dyninfo {
    print_address_info(argv)
  }
  if freespace {
    show_free_space(argv)
  }
}

func maxf(arr []float32) float32 {
  mx := float32(-42.42424242);
  for _, v := range arr {
    if v > mx {
      mx = v
    }
  }
  return mx
}

func interactive(argv []string) {
  proc, err := ptrace.Exec(argv[0], argv)
  if err != nil {
    log.Fatalf("could not start program: %v\n", err)
  }
  <- proc.Events() // eat initial 'process is starting' notification.
  defer proc.Close()

  if err := MainSync(argv[0], proc) ; err != nil {
    fmt.Printf("could not synchronize main! %v\n", err)
    return
  }

  cmds := Commands()
  events := proc.Events()
  fmt.Println("Please state the nature of the debugging emergency.")

  cmds <- nil
  for {
    select {
      case status := <-events:
        if status == nil {
          close(cmds)
          return
        }
        s := status.(syscall.WaitStatus)
        if s.Exited() {
          fmt.Println("\nprogram terminated.")
          close(cmds)
          return
        }
        if s.Signaled() {
          fmt.Printf("\nprogram terminated by signal %d\n", s.Signal())
          close(cmds)
          return
        }
      case cmd := <-cmds:
        if cmd == nil {
          fmt.Println("\nEOF, terminating.")
          return
        }
        if err := cmd.Execute(proc) ; err != nil {
          fmt.Fprintf(os.Stderr, "error executing command: %v\n", err)
        }
        cmds <- nil // signal that receiver can output && read next command
    }
  }
}

func symbol(symname string, symbols []bfd.Symbol) *bfd.Symbol {
  for _, sym := range symbols {
    if sym.Name() == symname {
      return &sym
    }
  }
  return nil
}

// Lets the inferior run until it hits 'main'.  We mostly use this to bypass
// all the application startup stuff (e.g. loading libc).  Afterwards, we can
// read symbols from the process and they'll have valid addresses.
// The loader has some special breakpoint hooks that we *should* use for
// identifying loaded and unloaded libraries.  This would allow us to account
// for libraries loaded at runtime (i.e. via dlopen), for example.  Currently
// we don't bother.
func MainSync(program string, inferior *ptrace.Tracee) error {
  symbols, err := bfd.Symbols(program)
  if err != nil { return err }

  symmain := symbol("main", symbols)
  // probably means 'program' isn't actually a program, maybe a SO or something.
  if symmain == nil { return fmt.Errorf("no 'main' function in symlist") }

  err = debug.WaitUntil(inferior, symmain.Address())
  if err == io.EOF {
    return fmt.Errorf("inferior exited before it hit main?")
  } else if err != nil { return err }

  iptr, err := inferior.GetIPtr()
  if err != nil { return err }
  // now we're at main and the program is stopped.
  fmt.Printf("[s] process %d hit main at 0x%0x\n", inferior.PID(), iptr)

  // not sure this belongs here, but we need these and this is the first place
  // we can actually read symbols from the process.
  globals.symbols, err = bfd.SymbolsProcess(inferior)
  if err != nil {
    return err
  }
  globals.program = program

  return nil
}

// A FuncABI reads and writes information from the inferior's stack.
// This is used for reading arguments of functions, as well as their
// return values.  Implementations are ABI-specific.
// Typing is often not accurately represented.  For example, the
// first argument to 'malloc' is best modelled as Go's uint, whereas
// the first argument to 'strlen' is best modelled as Go's uintptr.
// We use uint64s here and expect users to cast.
type FuncABI interface {
  Arg1(*ptrace.Tracee) uint64
  SetArg1(*ptrace.Tracee, uint64) error
  RetAddr(*ptrace.Tracee) uintptr
  RetVal(*ptrace.Tracee) uint64
}
// x86_64 is a FuncABI implementation which conforms to the x86-64 ABI.
type x86_64 struct {}
// the x86-64 ABI places the first integer argument in RDI.
func (x86_64) Arg1(inferior *ptrace.Tracee) uint64 {
  regs, err := inferior.GetRegs()
  if err != nil { log.Fatalf(err.Error()) }
  return regs.Rdi
}
func (x86_64) SetArg1(inferior *ptrace.Tracee, value uint64) error {
  regs, err := inferior.GetRegs()
  if err != nil {
    return err
  }
  regs.Rdi = value
  return inferior.SetRegs(regs)
}
// in the x86-64 ABI, calling a function places the return address on the
// stack, and the RSP register points to that stack location.  So, essentially,
// *RSP is the return address.
// Note this is only valid *immediately* after the call: the code will very
// shortly afterwards muck with the stack (usually as the first instruction of
// the fqn).
func (x86_64) RetAddrTop(inferior *ptrace.Tracee) uintptr {
  regs, err := inferior.GetRegs()
  if err != nil { log.Fatalf(err.Error()) }

  retaddr, err := inferior.ReadWord(uintptr(regs.Rsp))
  if err != nil { log.Fatalf(err.Error()) }

  return uintptr(retaddr)
}

// Gets the return address when we are in the middle of a function.  The normal
// 'RetAddr' is only valid at the very start of a function (i.e. after it has
// been 'call'ed but before it does anything to its stack.
// Ouch.  We need to rename/reorganize this.
func (x86_64) RetAddrMid(inferior *ptrace.Tracee) uintptr {
  regs, err := inferior.GetRegs()
  if err != nil {
    log.Fatalf("could not get regs in middle of fqn: %v\n", err)
  }
  retaddr, err := inferior.ReadWord(uintptr(regs.Rbp+8))
  if err != nil {
    log.Printf("could not read 0x%0x: %v\n", uintptr(regs.Rbp+8), err)
    return 0x0
  }
  return uintptr(retaddr)
}

// This is complicated because x86_64 hates people.  At some arbitrary place
// inside the function, the return address is stored at [%rbp+8].  However, if
// we've just entered the function, the frame pointer isn't yet setup, so the
// return address is at [%rsp].
// We differentiate between the two by looking at the current instruction: if
// it's 'push %rbp', then we're at the top of the function; at no other place
// does that instruction make sense.  Otherwise, we assume that the frame
// pointer is valid and use that.  Note this logic is invalid for the small bit
// of code that is a function prologue/epilogue.  i.e. this will work if the
// current iptr is before or after the prologue, but not if we're *in* the
// prologue!
func (asm x86_64) RetAddr(inferior *ptrace.Tracee) uintptr {
  iptr, err := inferior.GetIPtr()
  if err != nil {
    log.Fatalf("grabbing insn ptr: %v\n", err)
  }
  insn := make([]byte, 1)
  if err := inferior.Read(iptr, insn) ; err != nil {
    log.Fatalf("could not read current (0x%x) instruction: %v\n", iptr, err)
  }
  // 0x55 is the machine code for 'push %rbp'.
  // 0xc3 is the machine code for 'ret'.
  if 0x55 == insn[0] || 0xc3 == insn[0] {
    return asm.RetAddrTop(inferior)
  }
  return asm.RetAddrMid(inferior)
}

// the x86-64 ABI places the return value in RAX.
func (x86_64) RetVal(inferior *ptrace.Tracee) uint64 {
  regs, err := inferior.GetRegs()
  if err != nil { log.Fatalf(err.Error()) }
  return regs.Rax
}

// forces the inferior to alloc a page && tells us that page's base address.
func getpage(inferior *ptrace.Tracee) (uintptr, error) {
  if err := verify_symbols_loaded(inferior) ; err != nil {
    return 0x0, err
  }

  mmap := symbol("mmap", globals.symbols)
  if mmap == nil {
    return 0x0, errors.New("'mmap' not in symbol list!")
  }
  main := symbol("main", globals.symbols)
  if main == nil {
    return 0x0, errors.New("'main' not in symbol list!")
  }

  addr, err := alloc_inferior(inferior, mmap.Address(), main.Address())
  if err != nil {
    return 0x0, err
  }

  return addr, nil
}

// We need to replace (some of) the inferior's mallocs with aligned
// allocations, so that we can write-protect the regions.  The replacement
// malloc must have the same signature; we think of ours as 'tjfmalloc'.
// Returns the address of the inserted function in the inferior's address
// space.
func setup_tjfmalloc(inferior *ptrace.Tracee) (uintptr, error) {
  if err := verify_symbols_loaded(inferior) ; err != nil {
    return 0x0, err
  }

  addr, err := getpage(inferior)
  if err != nil {
    return 0x0, err
  }

  malign := symbol("posix_memalign", globals.symbols)
  if malign == nil {
    return 0x0, errors.New("'posix_memalign' not in symbol list!")
  }
  mprot := symbol("mprotect", globals.symbols)
  if mprot == nil {
    return 0x0, errors.New("'mprotect' not in symbol list!")
  }
  _, err = fspace_fill(inferior, addr, malign.Address(), mprot.Address())
  if err != nil {
    return 0x0, err
  }
  return addr, nil
}

const(
  prot_NONE = 0x0
  prot_READ = 0x1
  prot_WRITE = 0x2
  prot_EXEC = 0x4
)

// like 'mprotect', but changes the inferior's memory protections, not ours.
// ADDR, LEN, and PROT are the arguments to mprotect.  This function makes the
// inferior run some code; RETTARGET is where it jumps back to when done.  If
// you only care for the side effect, use the current instruction ptr.
func iprotect(inferior *ptrace.Tracee, addr uintptr, len uint,
              prot uint64, rettarget uintptr) error {
  // We really should only be protecting pages.  We cannot really ensure that
  // the memory is for a single purpose, if we don't page-align everything.
  if uint64(addr) % 4096 != 0 || len % 4096 != 0 {
    return errors.New("memory is not page-aligned.")
  }
  if err := verify_symbols_loaded(inferior) ; err != nil {
    return err
  }

  mprotect := symbol("mprotect", globals.symbols)
  if mprotect == nil {
    return errors.New("'mprotect' not in symbol list!")
  }

  regs, err := inferior.GetRegs()
  if err != nil {
    return err
  }
  orig_regs := regs // copy registers.

  regs.Rdi = uint64(addr)
  regs.Rsi = uint64(len)
  regs.Rdx = prot
  regs.Rip = uint64(mprotect.Address())

  // 'ret' on x86_64 reads *%rsp and jumps to that.  The easiest solution to
  // control execution, then, is to fill *%rsp with where our caller wants the
  // inferior to jump back to.
  // But we don't just want to hack "arbitrary" memory locations in the
  // inferior.  Save what's there now so that we can restore it when we're done.
  oretaddr, err := inferior.ReadWord(uintptr(regs.Rsp))
  if err != nil {
    return fmt.Errorf("could not save retaddr: %v", err)
  }

  // now we can fill in our custom return address.
  err = inferior.WriteWord(uintptr(regs.Rsp), uint64(rettarget))
  if err != nil {
    return fmt.Errorf("could not replace *%%rsp with rettarget's addr: %v", err)
  }

  // Okay, now setup our registers for the mprotect arguments, + jump there.
  if err := inferior.SetRegs(regs) ; err != nil {
    return err
  }

  // We hacked our stack to return to rettarget; wait until that happens.
  if err := debug.WaitUntil(inferior, rettarget) ; err != nil {
    // A segfault is a pretty common error if you've mucked something up, like
    // given a terrible return address or something.  Try to give more info in
    // that case, it's really useful when debugging things like this.
    if err == debug.ErrSegFault {
      sig, err := inferior.GetSiginfo()
      if err != nil {
        return fmt.Errorf("error getting segfault reason: %v", err)
      }
      return fmt.Errorf("segfault@0x%x", sig.Addr)
    }
    return fmt.Errorf("did not return to target 0x%0x: %v", rettarget, err)
  }

  protection.Trace("%d on 0x%0x--0x%0x. SP: 0x%x -> 0x%x", prot, addr,
                   addr+uintptr(len), rettarget, oretaddr)
  // Now back to your regularly scheduled programming.
  if err := inferior.SetRegs(orig_regs) ; err != nil { // restore registers.
    return err
  }
  if err := inferior.WriteWord(uintptr(orig_regs.Rsp), oretaddr) ; err != nil {
    return err
  }
  return nil
}

// This forces the inferior to PROT_READ|PROT_WRITE the given chunk of memory.
// RETTARGET is where you'd like the inferior to return to.
func allow(inferior *ptrace.Tracee, addr uintptr, len uint,
           rettarget uintptr) error {
  return iprotect(inferior, addr, len, prot_READ|prot_WRITE, rettarget)
}

// Forces the inferior to PROT_READ a given chunk of memory.
// RETTARGET is where you'd like the inferior to return to.
func deny(inferior *ptrace.Tracee, addr uintptr, len uint,
          rettarget uintptr) error {
  return iprotect(inferior, addr, len, prot_READ, rettarget)
}

// An allocation that the inferior has performed.
// To make sure we don't get shared pages (multiple allocations on one page),
// we modify allocations to make sure they always start and end on page
// boundaries.  'length' and 'lpage' track the "user" allocation and the
// page-aligned end of allocation.
type allocation struct {
  base uintptr // the base address of the allocation
  length uint  // the length (bytes) of the allocation the user requested
  lpage uint64 // length (bytes) of our 'extended' version.  always
               // page-aligned, and always >= length.
}
// some convenience accessors because we care about the range so often.
func (a allocation) begin() uintptr { return a.base }
func (a allocation) end() uintptr { return a.base+uintptr(a.lpage) }
func (a allocation) String() string {
  return fmt.Sprintf("alloc(%d[%d]) : 0x%08x", a.length, a.lpage, a.base)
}

// an inferior event is some 'asynchronous' action that happens in the inferior.
type ievent interface {}

type trap struct {
  iptr uintptr
}
type segfault struct {
  addr uintptr
}

// tries to make inferior/event handling synchronous.  continuously runs
// inferior.Continue,
func ihandle(inferior *ptrace.Tracee) (ievent, error) {
  if err := inferior.Continue() ; err != nil {
    return nil, fmt.Errorf("continuing gave us an error: %v", err)
  }
  stat := <- inferior.Events()
  status := stat.(syscall.WaitStatus)
  if status.Exited() {
    return nil, io.EOF
  }

  switch {
  case status.StopSignal() == syscall.SIGSEGV:
    sig, err := inferior.GetSiginfo()
    if err != nil {
      return nil, err
    }
    iptr, err := inferior.GetIPtr()
    if err != nil {
      return nil, err
    }
    symb, err := find_function(iptr)
    if err != nil {
      return nil, err
    }
    protection.Trace("segfault at %s+%d: 0x%0x\n", symb.Name(),
                     iptr-symb.Address(), iptr)

    return segfault{addr: sig.Addr}, nil
  case status.Stopped() && status.StopSignal() == syscall.SIGTRAP:
    // back up once so the trap iptr makes sense and we can restart our insn
    if err := debug.Stepback(inferior) ; err != nil {
      return nil, err
    }
    ptr, err := inferior.GetIPtr()
    if err != nil {
      return nil, fmt.Errorf("signal %d and could not get iptr.",
                             status.StopSignal())
    }
    return trap{iptr: ptr}, nil
  case status.CoreDump():
    return nil, errors.New("abnormal termination (core dumped)")
  case status.Continued():
    return nil, fmt.Errorf("continued?  wtf? %v", status)
  case status.Stopped() && status.StopSignal() == syscall.SIGCHLD:
    // The process we are tracing had children, and its children (our
    // grandchildren) died.  This isn't an event we'd care about, so we just
    // 'skip' it by recursing.
    return ihandle(inferior)
  case status.Stopped():
    return nil, fmt.Errorf("trapped, not from BP: %v", status.TrapCause())
  }
  return status, fmt.Errorf("unknown wait status: %v", status)
}

// jumps can have many argument types, handle them appropriately.
func follow_jump(inferior *ptrace.Tracee, ixn x86asm.Inst,
                 address uintptr) uintptr {
  if ixn.Op != x86asm.JMP {
    panic("bad input: you should only give this function a jump instruction")
  }
  reloffset, isrel := ixn.Args[0].(x86asm.Rel)
  if isrel {
    return address + uintptr(reloffset)
  }

  memref, ismref := ixn.Args[0].(x86asm.Mem)
  if ismref {
    var mr uintptr
    switch memref.Base {
    case x86asm.RIP:
      // NOT regs.Rip: that'd be the current IPtr, not what the IPtr would be at
      // the given instruction.
      mr = address
    case x86asm.RBP:
      regs, err := inferior.GetRegs()
      if err != nil {
        protection.Error("could not get registers: %v\n", err)
      }
      mr = uintptr(regs.Rbp)
    default: protection.Error("unhandled register base: %v\n", memref)
    }
    return uintptr(int64(mr) + int64(int32(memref.Disp)))
  }
  protection.Error("not reloffset, not memref, what is this: %v?", ixn.Args[0])
  return 0x0 // i.e. an error
}

func find_opcode(opcode x86asm.Op, inferior *ptrace.Tracee,
                 startaddr uintptr) (uintptr, error) {
  insn := make([]byte, 16)
  addr := startaddr
  for {
    if err := inferior.Read(addr, insn) ; err != nil {
      return 0x0, err
    }
    ixn, err := x86asm.Decode(insn, 64)
    if err != nil {
      return 0x0, err
    }

    if opcode_in(ixn.Op, []x86asm.Op{opcode}) {
      return addr, nil
    }

    addr += uintptr(ixn.Len)
    // do we want to do this?
    if ixn.Op == x86asm.JMP { // follow unconditional jumps.
      addr = follow_jump(inferior, ixn, addr)
    }
  }
  return 0x0, errors.New("instruction never found")
}

// disgusting function to copy from a byte-slice-of-floats to an
// actual-slice-of-floats.  We need this because syscall.Ptrace*'s reads are
// broken, they should give an interface but give the byte array nonsense
// instead.
// syscall.PtracePeekData as well as our tfogal/ptrace 'Read' wrapper both take
// a []byte as the thing to read into.  This is arguably broken.
// We are working with floating point data, and thus have floating point arrays
// that we would like the data to be read into.  This hack is basically a cast
// that says 'give me a pointer to the same array, but make its type be
// compatible with the broken interface of 'Read' and syscall.PtracePeekData'.
func castf32b(data []float32) []byte {
  const SIZEOF_F32 = 4
  hdr := *(*reflect.SliceHeader)(unsafe.Pointer(&data))
  hdr.Len *= SIZEOF_F32
  hdr.Cap *= SIZEOF_F32
  dbyte := *(*[]byte)(unsafe.Pointer(&hdr))
  return dbyte
}

// starts up a new process, instrumented with our magic.
// make sure you 'Close' the returned process!
func instrument(argv []string) (*ptrace.Tracee, error) {
  inferior, err := ptrace.Exec(argv[0], argv)
  if err != nil {
    return nil, fmt.Errorf("could not start '%s': %v\n", argv[0], err)
  }
  <- inferior.Events() // eat initial 'process is starting' notification.

  if err := MainSync(argv[0], inferior) ; err != nil {
    inferior.Close()
    return nil, fmt.Errorf("main sync for '%s' failed: %v\n", argv[0], err)
  }

  tjfmalloc, err := setup_tjfmalloc(inferior)
  if err != nil {
    inferior.Close()
    return nil, fmt.Errorf("tjfmalloc failure: %v\n", err)
  }
  tmalloc := bfd.MakeSymbol("__tjfmalloc", tjfmalloc, 0)
  globals.symbols = append(globals.symbols, tmalloc)

  return inferior, nil
}

// Find the function's 'ret' instruction and insert a breakpoint there.
// It seems like this will fail if the function has multiple exit points.  I
// think we haven't hit that problem yet because compilers tend to structure
// all functions to essentially have a 'goto cleanup:' and then a single point
// of exit.  But there is, of course, no reason the compiler *needs* to do it
// this way.
// We should revisit this to be able to insert a breakpoint at *all* RET
// instructions within a function.  Better, we should have a separate function
// that identifies the list of all RETs within a function, and then functions
// which take such a list and enables/disables them.
func break_ret(inferior *ptrace.Tracee) (debug.Breakpoint, error) {
  symb, err := where(inferior)
  if err != nil {
    log.Fatalf("don't know where we are: %v\n", err)
  }
  // Search for the 'RET' as a location to insert our BP.
  ret, err := find_opcode(x86asm.RET, inferior, symb.Address())
  if err != nil {
    log.Fatalf("could not find RET starting from 0x%0x (%s)\n", symb.Address(),
               symb.Name())
  }
  protection.Trace("inserting BP at 0x%0x so we can re-enable " +
                   "memory protection.\n", ret)

  return debug.Break(inferior, ret)
}

// determines whether or not a symbol is a symbol that we might want to
// trace/care about it accessing memory of interest.  One example of an
// `uninteresting' function is calloc: it will write to the allocated
// memory, but we don't care about any write it would ever do.
func user_symbol(name string) bool {
  if strings.Contains(name, "@@") || strings.Contains(name, ".") {
    return false
  }
  if strings.HasPrefix(name, "H5") { // i.e. HDF5 symbols.
    return false
  }
  if strings.HasPrefix(name, "Py_") { // i.e. python symbols
    return false
  }
  if strings.HasPrefix(name, "_") { // internal gcc/glibc IO symbols
    return false
  }
  // internal gcc/glibc IO symbols
  if strings.HasPrefix(name, "MPI_") || strings.HasPrefix(name, "mpi_") {
    return false
  }
  syms := []string{
    "argz_append",
    "argz_create_sep",
    "getdelim",
    "getpwuid",
    "ntp_gettimex",
    "strdup",
    "tsearch",
    "vasprintf",
    "envz_strip", "fgets", "free", "getpagesize", "mmap", "memccpy", "memset",
    "mprotect", "posix_memalign",
  }

  for _, s := range syms {
    if s == name {
      return false
    }
  }
  return true
}

func bounds(program string, inferior *ptrace.Tracee) ([]uint, error) {
  symbol, err := where(inferior)
  if err != nil {
    log.Fatalf("Cannot find where we are: %v", err)
  }
  if !user_symbol(symbol.Name()) {
    // then it's a C library function, don't bother, it's probably
    // calloc or something that would access the memory but not do anything
    // that gives us extra information.
    return nil, fmt.Errorf("%s is a library function, ignoring", symbol.Name())
  }
  protection.Trace("building CFG for %s@0x%0x", symbol.Name(), symbol.Address())
  graph := cfg.FromAddress(program, symbol.Address())
  if rn := root_node(graph, symbol) ; rn != nil {
    cfg.Analyze(rn)
  }
  bb, err := basic_block(graph, whereis(inferior))
  if err != nil { // Don't know where we are, then.
    log.Fatalf("It is pitch dark.  We have been eaten by a grue: %v", err)
  }
  return bind_identify(symbol.Name(), bb, inferior)
}

// A process / shared library leaves some free space after it's loaded.  This
// finds the first such free space.
func free_space_address(pid int) (uintptr, error) {
  filename := fmt.Sprintf("/proc/%d/maps", pid)
  maps, err := os.Open(filename)
  if err != nil {
    return 0x0, err
  }
  defer maps.Close()

  // an example /proc/$pid/maps entry is:
  // address           perms offset  dev   inode   pathname
  // 08048000-08056000 r-xp 00000000 03:0c 64593   /path/to/executable/or/lib
  // we search for the first address which has a device of 00:00, which
  // (supposedly?) implies that this is 'free space', unused by the process.
  scanner := bufio.NewScanner(maps)
  var addr uintptr
  for scanner.Scan() {
    line := scanner.Text()
    var junk string
    var junkaddr uintptr
    var device string
    var inode uint
    _, err = fmt.Sscanf(line, "%x-%x %s %s %s %d", &addr, &junkaddr, &junk,
                        &junk, &device, &inode)
    // err could be EOF.  That means there's no free space.  Grumble.
    // But it seems libc has some free space, so we probably don't need to
    // worry about that in practice.
    if err != nil { return 0x0, err }

    if device == "00:00" && inode == 0 {
      break
    }
  }
  return addr, nil
}

// temp hack for testing free space stuff
func show_free_space(argv []string) {
  inferior, err := ptrace.Exec(argv[0], argv)
  if err != nil {
    log.Fatalf("could not start program '%v': %v\n", argv, err)
  }
  defer inferior.Close()
  <-inferior.Events() // eat initial 'process is starting' notification.
  if err := MainSync(argv[0], inferior) ; err != nil { // run until main
    fmt.Printf("could not sync with main: %v\n", err)
    return
  }

  if err := verify_symbols_loaded(inferior) ; err != nil {
    log.Fatalf("error reading symbols: %v\n", err)
  }

  // these symbols are part of libc; if they're not there, i can't imagine we'd
  // have made it here.
  assert(symbol("getpagesize", globals.symbols) != nil)
  assert(symbol("posix_memalign", globals.symbols) != nil)

  fspace_fill(inferior, symbol("getpagesize", globals.symbols).Address(),
              symbol("posix_memalign", globals.symbols).Address(),
              symbol("mprotect", globals.symbols).Address())
}

// slice[i] = word[i] forall i in word
func replace(slice []uint8, word int32) {
  // it's ill-defined what we want to replace if they give us >4 bytes.
  if len(slice) != 4 {
    panic("this assumes we are replacing a 4 byte quantity!!")
  }
  buf := new(bytes.Buffer)
  binary.Write(buf, binary.LittleEndian, word)
  bts := buf.Bytes()
  slice[0] = bts[0]; slice[1] = bts[1]
  slice[2] = bts[2]; slice[3] = bts[3]
}

// Identifies a part of our address space that is unused.  Then fills it with a
// function that will posix_memalign-allocate some memory.
// Returns the starting/ending addresses of the created code.
func fspace_fill(inferior *ptrace.Tracee, addr uintptr,
                 memalign uintptr, mprotect uintptr) (uintptr, error) {
  // we're essentially defining the function:
  //   void* fqn(size_t n) {
  //     void* mem = NULL;
  //     posix_memalign(&mem, 4096, n);
  //     if(mem == NULL) {
  //       return NULL;
  //     }
  //     mprotect(mem, n, PROT_READ);
  //     return mem;
  //   }
  // but in pure object code.  Note that the above relies on posix_memalign not
  // changing 'mem' when it fails, which isn't necessarily guaranteed... 
  memalign_code := []byte{
    0x55,                           // push   %rbp
    0x48, 0x89, 0xe5,               // mov    %rsp,%rbp
    0x48, 0x83, 0xec, 0x20,         // sub    $0x20,%rsp
    0x48, 0x89, 0x7d, 0xe8,         // mov    %rdi,-0x18(%rbp)
    0x48, 0xc7, 0x45, 0xf8,         // movq   ...
      0x00, 0x00, 0x00, 0x00,       // ...    $0x0,-0x8(%rbp)
    0x48, 0x8b, 0x55, 0xe8,         // mov    -0x18(%rbp),%rdx
    0x48, 0x8d, 0x45, 0xf8,         // lea    -0x8(%rbp),%rax
    0xbe, 0x00, 0x10, 0x00, 0x00,   // mov    $0x1000,%esi
    0x48, 0x89, 0xc7,               // mov    %rax,%rdi
    0xe8, 0xFF, 0xFF, 0xFF, 0xFF,   // callq  POSIX_MEMALIGN
    // The FF's are a reloffset; we cannot know them statically. See below.
    0x48, 0x8b, 0x45, 0xf8,         // mov    -0x8(%rbp),%rax
    0x48, 0x85, 0xc0,               // test   %rax,%rax
    0x75, 0x07,                     // jne    4005c6 <aalloc+0x39>
    0xb8, 0x00, 0x00, 0x00, 0x00,   // mov    $0x0,%eax
    0xeb, 0x1c,                     // jmp    4005e2 <aalloc+0x55>
    0x48, 0x8b, 0x45, 0xf8,         // mov    -0x8(%rbp),%rax
    0x48, 0x8b, 0x4d, 0xe8,         // mov    -0x18(%rbp),%rcx
    0xba, 0x01, 0x00, 0x00, 0x00,   // mov    $0x1,%edx
    0x48, 0x89, 0xce,               // mov    %rcx,%rsi
    0x48, 0x89, 0xc7,               // mov    %rax,%rdi
    0xe8, 0xFF, 0xFF, 0xFF, 0xFF,   // callq MPROTECT
    0x48, 0x8b, 0x45, 0xf8,         // mov    -0x8(%rbp),%rax
    0xc9,                           // leaveq
    0xc3,                           // retq
  }

  // Now we have to fix up the 'call' address that is filled with "0xFF" (note
  // caps) above.  We need to fill that 32bit space with the *relative* address
  // of posix_memalign.  It's relative to the instruction pointer, but not the
  // instruction pointer /now/, rather the address of the END of the call
  // instruction (i.e. address of the instruction after the call).
  // Since we're going to fill 'addr' with this function, that can serve as our
  // base address.  Then it's just an issue of counting bytes.
  //malign_addr := addr + 23
  const maoffset = 36
  malign_addr := addr + maoffset
  malign_end_addr := malign_addr + 5
  malign_reladdr := int64(memalign) - int64(malign_end_addr)
  if malign_reladdr != int64(int32(malign_reladdr)) { // does it fit in 32bit?
    panic("can't encode jump to posix_memalign as a near call!")
  }
  // maoffset bytes in is the 'e8' of our call.  We want to replace the
  // argument, which is 1 past that, and is 4 bytes long.
  replace(memalign_code[maoffset+1:maoffset+1+4], int32(malign_reladdr))

  const mpoffset = 76
  mp_addr := addr + mpoffset
  mp_end_addr := mp_addr + 5
  mp_reladdr := int64(mprotect) - int64(mp_end_addr)
  if mp_reladdr != int64(int32(mp_reladdr)) { // does it fit in 32bit?
    panic("can't encode 'call mprotect' as a near call!")
  }
  // mpoffset bytes in is the 'e8' of our call.  We want to replace the
  // argument, which is 1 past that, and is 4 bytes long.
  replace(memalign_code[mpoffset+1:mpoffset+1+4], int32(mp_reladdr))

  // This is just for debugging, so we can see if what we put in there is valid.
  asm := new(bytes.Buffer)
  fmt.Fprintf(asm, "buf:\n")
  for i,v := range memalign_code {
    if (i >= maoffset+1 && i <= maoffset+1+4) ||
       (i >= mpoffset+1 && i <= mpoffset+1+4) { // the replaced addresses
      fmt.Fprintf(asm, "0x%02X ", v)
    } else {
      fmt.Fprintf(asm, "0x%02x ", v) // note lowercase
    }
    if i != 0 && (i % 15) == 0 { fmt.Fprintf(asm, "\n") }
  }
  fmt.Fprintf(asm, "\n")
  decode(memalign_code, asm)
  inject.Trace(asm.String())

  if err := inferior.Write(addr, memalign_code) ; err != nil {
    return 0x0, err
  }

  end_addr := addr + uintptr(uint(len(memalign_code)))
  return end_addr, nil
}

// this creates the function:
//   void allow(void* base, size_t len) {
//     mprotect(base, len, PROT_READ | PROT_WRITE);
//   }
// at ADDR.  MPROT must be the address of 'mprotect'.
// ... This isn't used.  mprotect is just a single, easy call, so we just hack
// the instruction pointer to jump to it.
func fill_unprotect(inferior *ptrace.Tracee, addr uintptr,
                    mprotect uintptr) (uintptr, error) {
  allow_code := []byte{
    0x55,                         // push   %rbp
    0x48, 0x89, 0xe5,             // mov    %rsp,%rbp
    0x48, 0x83, 0xec, 0x10,       // sub    $0x10,%rsp
    0x48, 0x89, 0x7d, 0xf8,       // mov    %rdi,-0x8(%rbp)
    0x48, 0x89, 0x75, 0xf0,       // mov    %rsi,-0x10(%rbp)
    0x48, 0x8b, 0x4d, 0xf0,       // mov    -0x10(%rbp),%rcx
    0x48, 0x8b, 0x45, 0xf8,       // mov    -0x8(%rbp),%rax
    0xba, 0x03, 0x00, 0x00, 0x00, // mov    $0x3,%edx
    0x48, 0x89, 0xce,             // mov    %rcx,%rsi
    0x48, 0x89, 0xc7,             // mov    %rax,%rdi
    0xe8, 0xFF, 0xFF, 0xFF, 0xFF, // callq  MPROTECT
    0xc9,                         // leaveq
    0xc3,                         // retq
  }
  // now fix up the 'mprotect' address.
  const mpoffs = 35
  mprot_addr := addr + mpoffs
  mprot_end_addr := mprot_addr + 5
  mprot_reladdr := int64(mprotect) - int64(mprot_end_addr)
  if mprot_reladdr != int64(int32(mprot_reladdr)) { // does it fit in 32bit?
    panic("can't encode jump to mprotect as a near call!")
  }
  // mpoffs bytes into our buffer is the 'e8' of our call.  We want to replace
  // the argument, which is 1 past that, and is 4 bytes long.
  replace(allow_code[mpoffs+1:mpoffs+1+4], int32(mprot_reladdr))

  // Purely for debugging.
  asm := new(bytes.Buffer)
  fmt.Fprintf(asm, "allowfqn:\n")
  for i,v := range allow_code {
    if i >= mpoffs+1 && i <= mpoffs+1+4 { // the replaced address
      fmt.Fprintf(asm, "0x%02X ", v)
    } else {
      fmt.Fprintf(asm, "0x%02x ", v) // note lowercase
    }
    if i != 0 && (i % 15) == 0 { fmt.Fprintf(asm, "\n") }
  }
  fmt.Fprintf(asm, "\n")
  decode(allow_code, asm)
  inject.Trace(asm.String())

  if err := inferior.Write(addr, allow_code) ; err != nil {
    return 0x0, err
  }

  end_addr := addr + uintptr(uint(len(allow_code)))
  return end_addr, nil
}

func decode(memory []byte, strm io.Writer) {
  for offset := 0 ; offset < len(memory) ; {
    ixn, err := x86asm.Decode(memory[offset:], 64)
    if err != nil { panic(err) }
    fmt.Fprintf(strm, "\t%v\n", ixn)
    offset += ixn.Len
  }
}

// This creates an executable chunk of memory in the inferior's address space
// that we can then use for our nefarious purposes.  It overwrites the
// registers and instruction pointer so that, instead of executing the next
// instruction, the inferior instead calls
//   mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
// Then it pulls out the return address from mmap---the address of the memory
// we want---and restores all the original registers and instruction pointer.
// Returns the retval of mmap.
// Must be called when the inferior is stopped *AT*'main'*!
// This is cool; and by cool, I mean totally sweet.
func alloc_inferior(inferior *ptrace.Tracee, mmap uintptr,
                    main uintptr) (uintptr, error) {
  regs, err := inferior.GetRegs()
  if err != nil {
    return 0x0, err
  }
  orig_regs := regs // copy registers.

  if uintptr(regs.Rip) != main {
    fmt.Printf("main is: 0x%0x and we are at 0x%0x\n", main, uintptr(regs.Rip))
    return 0x0, fmt.Errorf("not at main")
  }

  regs.Rdi = 0x0 // addr
  regs.Rsi = 0x1000 // length
  regs.Rdx = 0x5 // prot
  regs.Rcx = 0x22 // flags
  regs.R8 = 0xffffffffffffffff // fd, aka -1
  regs.R9 = 0
  if int64(regs.R8) != -1 {
    return 0x0, fmt.Errorf("our 'fd' argument to mmap is incorrect..")
  }

  regs.Rax = 0xdeadbeef // for testing/making sure our retval is valid.
  regs.Rip = uint64(mmap)

  // The 'ret' insruction reads *%rsp and jumps back to that.  So fill *%rsp
  // with the address of 'main'.  But save what's there at the moment, so we
  // can restore it later.
  // That said, we're just starting main, so whatever's in %rsp is probably
  // garbage.  But i'm a stickler for 'leave no trace', soooo....
  stackptr, err := inferior.ReadWord(uintptr(regs.Rsp))
  if err != nil {
    return 0x0, err
  }
  if err := inferior.WriteWord(uintptr(regs.Rsp), uint64(main)) ; err != nil {
    return 0x0, fmt.Errorf("could not replace *%rsp with main's addr: %v", err)
  }

  // Okay, now setup our registers for the mmap arguments and jump there.
  if err := inferior.SetRegs(regs) ; err != nil {
    return 0x0, err
  }
  // We hacked our stack to return to main; wait until that happens.
  if err := debug.WaitUntil(inferior, main) ; err != nil {
    return 0x0, fmt.Errorf("did not return to main: %v", err)
  }

  // We're back from main.  What did 'mmap' give us?
  var stk x86_64
  retval := uintptr(stk.RetVal(inferior))
  if retval == 0xdeadbeef || int64(retval) == -1 {
    panic("mmap gave us back -1, we must have broken its args or something")
  }

  // I'm so hilarious:
  fmt.Println("[s] Now back to your regularly scheduled programming.")
  if err := inferior.SetRegs(orig_regs) ; err != nil {
    return 0x0, err
  }
  if err := inferior.WriteWord(uintptr(orig_regs.Rsp), stackptr) ; err != nil {
    return 0x0, fmt.Errorf("could not reset *%rsp with correct addr: %v", err)
  }
  return retval, nil
}

// dumps some instructions from the current insn ptr to stdout
func insns_stdout(inferior *ptrace.Tracee) error {
  regs, err := inferior.GetRegs()
  if err != nil {
    return err
  }

  mem := make([]byte, 24)
  if err := inferior.Read(uintptr(regs.Rip), mem) ; err != nil {
    return err
  }
  fmt.Printf("instructions from 0x%0x\n", regs.Rip)
  decode(mem, os.Stdout)
  return nil
}
