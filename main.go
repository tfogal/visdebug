package main;

import(
  "bufio"
  "errors"
  "flag"
  "fmt"
  "io"
  "os"
  "log"
  "strings"
  "syscall"
  "github.com/tfogal/ptrace"
  "./bfd"
  "./cfg"
  "./debug"
)

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
    panic("assertion failure")
  }
}

var symlist bool
var execute bool
var dotcfg bool
var showmallocs bool
var dyninfo bool
var freespace bool
func init() {
  flag.BoolVar(&symlist, "symbols", false, "print out the symbol table")
  flag.BoolVar(&symlist, "s", false, "print out the symbol table")
  flag.BoolVar(&execute, "x", false, "execute subprogram")
  flag.BoolVar(&dotcfg, "cfg", false, "compute and print CFG")
  flag.BoolVar(&showmallocs, "mallocs", false, "print a line per malloc")
  flag.BoolVar(&dyninfo, "attach", false, "attach and print dynamic info")
  flag.BoolVar(&freespace, "free", false, "show maps and find first free space")
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
    interactive(argv)
  }
  if showmallocs {
    mallocs(argv)
  }
  if dyninfo {
    print_address_info(argv)
  }
  if freespace {
    show_free_space(argv)
  }
}

func interactive(argv []string) {
  proc, err := ptrace.Exec(argv[0], argv)
  if err != nil {
    log.Fatalf("could not start program: %v\n", err)
  }

  cmds := Commands()

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

func symbol(symname string, symbols []bfd.Symbol) *bfd.Symbol {
  for _, sym := range symbols {
    if sym.Name() == symname {
      return &sym
    }
  }
  return nil
}

func iptr(inf *ptrace.Tracee) uintptr {
  addr, err := inf.GetIPtr()
  if err != nil { log.Fatalf(err.Error()) }
  return addr
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
  fmt.Printf("[go] hit main at 0x%0x\n", iptr)

  // now we're at main and the program is stopped.
  return nil
}

// A StackReader reads information from the inferior's stack.  This is used for
// reading arguments of functions, as well as their return values.
// Implementations are ABI-specific.
// Typing is often not accurately represented.  For example, the
// first argument to 'malloc' is best modelled as Go's uint, whereas
// the first argument to 'strlen' is best modelled as Go's uintptr.
// Thus we use uint64's often, here, and expect users to cast.
type StackReader interface {
  Arg1(*ptrace.Tracee) uint64
  RetAddr(*ptrace.Tracee) uintptr
  RetVal(*ptrace.Tracee) uint64
}
// x86_64 is a StackReader implementation which conforms to the x86-64 ABI.
type x86_64 struct {}
// the x86-64 ABI places the first integer argument in RDI.
func (x86_64) Arg1(inferior *ptrace.Tracee) uint64 {
  regs, err := inferior.GetRegs()
  if err != nil { log.Fatalf(err.Error()) }
  return regs.Rdi
}
// in the x86-64 ABI, calling a function places the return address on the
// stack, and the RSP register points to that stack location.  So, essentially,
// *RSP is the return address.
// If we're in the "root" or entry function, then this function makes no sense
// and will likely return garbage.
func (x86_64) RetAddr(inferior *ptrace.Tracee) uintptr {
  regs, err := inferior.GetRegs()
  if err != nil { log.Fatalf(err.Error()) }

  retaddr, err := inferior.ReadWord(uintptr(regs.Rsp))
  if err != nil { log.Fatalf(err.Error()) }

  return uintptr(retaddr)
}
// the x86-64 ABI places the return value in RAX.
func (x86_64) RetVal(inferior *ptrace.Tracee) uint64 {
  regs, err := inferior.GetRegs()
  if err != nil { log.Fatalf(err.Error()) }
  return regs.Rax
}

func mallocs(argv []string) {
  inferior, err := ptrace.Exec(argv[0], argv)
  if err != nil {
    log.Fatalf("could not start program: %v", err)
  }
  <- inferior.Events() // eat initial 'process is starting' notification.
  defer inferior.Close()

  MainSync(argv[0], inferior)

  symbols, err := bfd.SymbolsProcess(inferior)
  if err != nil {
    log.Fatalf("could not read inferior's symbols: %v\n", err)
  }
  symmalloc := symbol("malloc", symbols)
  if symmalloc == nil {
    fmt.Fprintf(os.Stderr, "Binary does not use 'malloc'.  Giving up.\n")
    inferior.SendSignal(syscall.SIGTERM)
    return
  }

  var stk x86_64
  for {
    fmt.Printf("waiting for malloc at 0x%0x\n", symmalloc.Address())
    err = debug.WaitUntil(inferior, symmalloc.Address())
    if err == io.EOF {
      break
    } else if err != nil {
      fmt.Fprintf(os.Stderr, "[go] application exited abnormally: %v\n", err)
      break;
    }
    // At this point, we hit 'malloc'.  Let's examine the registers/stack to
    // figure out how many bytes were given to malloc, as well as where malloc
    // is going to return to.
    nbytes := stk.Arg1(inferior)
    retsite := stk.RetAddr(inferior)
    fmt.Printf("[go] malloc(%4d) -> ", nbytes)

    err = debug.WaitUntil(inferior, retsite)
    fmt.Printf("0x%08x\n", uintptr(stk.RetVal(inferior)))
  }
  fmt.Printf("[go] inferior (%d) terminated.\n", inferior.PID())
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
  MainSync(argv[0], inferior) // run until we hit main, then pause.

  symbols, err := bfd.SymbolsProcess(inferior)
  if err != nil { log.Fatalf("could not read smbols: %v\n", err) }

  // these symbols are part of libc; if they're not there, i can't imagine we'd
  // have made it here.
  assert(symbol("getpagesize", symbols) != nil)
  assert(symbol("posix_memalign", symbols) != nil)

  fspace_addr(inferior.PID())
  inferior.Close()
}

func fspace_addr(pid int) {
  viewmaps(pid)

  addr, err := free_space_address(pid)
  if err != nil {
    panic(err)
  }

  fmt.Printf("first freespace addr is at: 0x%0x\n", addr)

  // at the time we get called, we're at a breakpoint for malloc.  so our
  // replacement function has malloc's argument (n bytes) in RDI, and we need
  // to fill RAX with whatever posix_memalign gives.
  memalign_code := []uint8{
    0x55,             // push %rbp
    0x48, 0x89, 0xe5, // mov %rsp, %rbp
    0x48, 0x83, 0xec, 0x20, // sub $0x20, %rsp  ; reserve 32bytes of stack
    0x48, 0x89, 0x78, 0xe8, // mov %rdi, -0x18(%rbp)
    0x48, 0xc7, 0x45, 0x48, 0x00, 0x00, 0x00, 0x00, // movq $0, -0x8(%rbp)
    // e8 d2 fe ff ff          callq  600 <getpagesize@plt>
    0x48, 0x63, 0xc8, // movlsq %eax, %rcx ; sign-extend GPS return value
    0x48, 0x8b, 0x55, 0xe8, // mov -0x18(%rbp), %rdx
    0x48, 0x8d, 0x45, 0xf8, // lea -0x8(%rbp), %rax  ; 1st stackvar to RAX
    0x48, 0x89, 0xce, // mov %rcx, %rsi  ; GPS retval (in RCX) is 2nd arg
    0x48, 0x89, 0xc7, // mov %rax, %rdi  ; 1st arg is from 1st stackvar
    // e8 cc fe ff ff          callq  610 <posix_memalign@plt>
    0x48, 0x8b, 0x45, 0xf8, // mov -0x8(%rbp), %rax
    0xc9, // leaveq
    0xc3, // retq
  }
  _ = memalign_code
}
