package main;

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
  "runtime/pprof"
  "strings"
  "syscall"
  "github.com/tfogal/ptrace"
  "code.google.com/p/rsc.x86/x86asm"
  "./bfd"
  "./cfg"
  "./debug"
  "./msg"
)

// for information regarding code injection
var inject = msg.StdChan()

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
var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
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

  if *cpuprofile != "" {
    f, err := os.Create(*cpuprofile)
    if err != nil { panic(err) }
    pprof.StartCPUProfile(f)
    defer pprof.StopCPUProfile()
  }

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
  <- proc.Events() // eat initial 'process is starting' notification.
  defer proc.Close()

  if err := MainSync(argv[0], proc) ; err != nil {
    fmt.Printf("could not synchronize main! %v\n", err)
    return
  }

  cmds := Commands(CmdGlobal{argv[0]})

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
  fmt.Printf("[go] process %d hit main at 0x%0x\n", inferior.PID(), iptr)

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

// forces the inferior to alloc a page && tells us that page's base address.
func getpage(inferior *ptrace.Tracee) (uintptr, error) {
  symbols, err := bfd.SymbolsProcess(inferior)
  if err != nil {
    return 0x0, err
  }

  mmap := symbol("mmap", symbols)
  if mmap == nil {
    return 0x0, errors.New("'mmap' not in symbol list!")
  }
  main := symbol("main", symbols)
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
  symbols, err := bfd.SymbolsProcess(inferior)
  if err != nil {
    return 0x0, err
  }

  addr, err := getpage(inferior)
  if err != nil {
    return 0x0, err
  }

  malign := symbol("posix_memalign", symbols)
  if malign == nil {
    return 0x0, errors.New("'posix_memalign' not in symbol list!")
  }
  mprot := symbol("mprotect", symbols)
  if mprot == nil {
    return 0x0, errors.New("'mprotect' not in symbol list!")
  }
  _, err = fspace_fill(inferior, addr, malign.Address(), mprot.Address())
  if err != nil {
    return 0x0, err
  }
  return addr, nil
}

// creates a function that allows us to change a memory region's protection.
// ... actually, this isn't used.  Since it's just a single call to mprotect,
// we just do it by hacking the registers/stack to be what we want.  See the
// 'allow' function.
func setup_unprotect(inferior *ptrace.Tracee) (uintptr, error) {
  addr, err := getpage(inferior)
  if err != nil {
    return 0x0, err
  }

  symbols, err := bfd.SymbolsProcess(inferior)
  if err != nil {
    return 0x0, err
  }
  mprot := symbol("mprotect", symbols)
  if mprot == nil {
    return 0x0, errors.New("'mprotect' not in symbol list!")
  }

  _, err = fill_unprotect(inferior, addr, mprot.Address())
  if err != nil {
    return 0x0, err
  }

  return addr, nil
}

// This forces the inferior to PROT_READ|PROT_WRITE the given chunk of memory.
// RETTARGET is where you'd like the inferior to return to.
func allow(inferior *ptrace.Tracee, addr uintptr, len uint,
           rettarget uintptr) error {
  symbols, err := bfd.SymbolsProcess(inferior)
  if err != nil {
    return err
  }
  mprotect := symbol("mprotect", symbols)
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
  regs.Rdx = 0x3 // prot, i.e. PROT_READ | PROT_WRITE
  regs.Rip = uint64(mprotect.Address())

  // The 'ret' insruction reads *%rsp and jumps back to that.  So fill *%rsp
  // with whereever the user wanted to jump back to.
  err = inferior.WriteWord(uintptr(regs.Rsp), uint64(rettarget))
  if err != nil {
    return fmt.Errorf("could not replace *%rsp with rettarget's addr: %v", err)
  }

  // Okay, now setup our registers for the mprotect arguments and jump there.
  if err := inferior.SetRegs(regs) ; err != nil {
    return err
  }
  // We hacked our stack to return to rettarget; wait until that happens.
  if err := debug.WaitUntil(inferior, rettarget) ; err != nil {
    return fmt.Errorf("did not return to to target: %v", err)
  }

  fmt.Printf("[go] Allowed 0x%0x. ", addr)
  // I'm so hilarious:
  fmt.Println("Now back to your regularly scheduled programming.")
  if err := inferior.SetRegs(orig_regs) ; err != nil { // restore registers.
    return err
  }
  return nil
}

// An allocation that the inferior has performed.
type allocation struct {
  base uintptr
  length uint
}
// some convenience accessors because we care about the range so often.
func (a allocation) begin() uintptr { return a.base }
func (a allocation) end() uintptr { return a.base+uintptr(a.length) }

func find_alloc(allocs []allocation, addr uintptr) (allocation, error) {
  for _, alc := range allocs {
    if alc.begin() <= addr && addr <= alc.end() {
      return alc, nil
    }
  }
  return allocation{}, fmt.Errorf("allocation 0x%0x not found", addr)
}

// runs a program, replacing every 'malloc' in a program with
// 'tjfmalloc'---a faux malloc implementation that forwards to
// posix_memalign && mprotect.
func mallocs(argv []string) {
  inferior, err := ptrace.Exec(argv[0], argv)
  if err != nil {
    log.Fatalf("could not start program: %v", err)
  }
  <- inferior.Events() // eat initial 'process is starting' notification.
  defer inferior.Close()

  if err := MainSync(argv[0], inferior) ; err != nil {
    fmt.Printf("main sync failed: %v\n", err)
    return
  }

  symbols, err := bfd.SymbolsProcess(inferior)
  if err != nil {
    log.Fatalf("could not read inferior's symbols: %v\n", err)
  }
  symmalloc := symbol("malloc", symbols)
  if symmalloc == nil {
    log.Fatalf("Binary does not have 'malloc'.  Giving up.\n")
    return
  }
  tjfmalloc, err := setup_tjfmalloc(inferior)
  if err != nil {
    log.Fatalf("could not setup replacement malloc: %v\n", err)
    return
  }

  allocs := make([]allocation, 0)
  var stk x86_64
  for {
    fmt.Printf("[go] waiting for malloc at 0x%0x\n", symmalloc.Address())
    err = debug.WaitUntil(inferior, symmalloc.Address())
    if err == io.EOF {
      break
    } else if err == debug.ErrSegFault {
      sigi, err := inferior.GetSiginfo()
      if err != nil {
        fmt.Fprintf(os.Stderr, "[go] error getting siginfo: %v\n", err)
        return
      }
      fmt.Printf("[go] process %d segfaulted (%d) at address 0x%0x ",
                 inferior.PID(), sigi.Signo, sigi.Addr)
      fmt.Printf("(errno=%d, code=%d, trapno=%d)\n", sigi.Errno, sigi.Code,
                 sigi.Trapno)
      alc, err := find_alloc(allocs, sigi.Addr)
      if err != nil { // then it was just a normal segfault.  die.
        break
      }
      fmt.Printf("[go] accessed allocation 0x%0x--0x%0x (0x%0x)\n", alc.begin(),
                 alc.end(), sigi.Addr)
      retsite := stk.RetAddr(inferior)
      fmt.Printf("[go] will allow it and then return to 0x%0x\n", retsite)
      if err := inferior.ClearSignal() ; err != nil {
        log.Fatalf("could not clear segv: %v\n", err)
      }
      if err := allow(inferior, alc.base, alc.length, retsite) ; err != nil {
        log.Fatalf("could not allow 0x%0x\n", alc.base)
      }
      continue
    } else if err != nil {
      fmt.Fprintf(os.Stderr, "[go] application exited abnormally: %v\n", err)
      break
    }
    // At this point, we hit 'malloc'.  Let's examine the registers/stack to
    // figure out how many bytes were given to malloc, as well as where malloc
    // is going to return to.
    nbytes := stk.Arg1(inferior)
    retsite := stk.RetAddr(inferior)

    // instead of letting it run, 'jump' to tjfmalloc.
    if err := inferior.SetIPtr(tjfmalloc) ; err != nil {
      log.Fatalf("could not reset iptr when replacing alloc: %v\n", err)
      return
    }
    // now let it go, but stop when we come back from the function.
    if err := debug.WaitUntil(inferior, retsite) ; err != nil {
      log.Fatalf("waiting for tjfmalloc to complete: %v\n", err)
      return
    }
    rval := stk.RetVal(inferior)
    alc := allocation{base: uintptr(rval), length: uint(nbytes)}
    allocs = append(allocs, alc)
    fmt.Printf("[go] malloc(%4d) -> 0x%08x--0x%08x\n", alc.length, alc.base,
               alc.base+uintptr(alc.length))
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
  if err := MainSync(argv[0], inferior) ; err != nil { // run until main
    fmt.Printf("could not sync with main: %v\n", err)
    return
  }

  symbols, err := bfd.SymbolsProcess(inferior)
  if err != nil { log.Fatalf("could not read smbols: %v\n", err) }

  // these symbols are part of libc; if they're not there, i can't imagine we'd
  // have made it here.
  assert(symbol("getpagesize", symbols) != nil)
  assert(symbol("posix_memalign", symbols) != nil)

  fspace_fill(inferior, symbol("getpagesize", symbols).Address(),
              symbol("posix_memalign", symbols).Address(),
              symbol("mprotect", symbols).Address())
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
  save_stack, err := inferior.ReadWord(uintptr(regs.Rsp))
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
  fmt.Println("[go] Now back to your regularly scheduled programming.")
  if err := inferior.SetRegs(orig_regs) ; err != nil {
    return 0x0, err
  }
  if err := inferior.WriteWord(uintptr(regs.Rsp), save_stack) ; err != nil {
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
