package main;

import(
  "bufio"
  "bytes"
  "encoding/binary"
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
              symbol("posix_memalign", symbols).Address())
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
func fspace_fill(inferior *ptrace.Tracee, getpagesize uintptr,
                 memalign uintptr) (uintptr, error) {
  //viewmaps(inferior.PID())

  addr, err := free_space_address(inferior.PID())
  if err != nil { return 0x0, err }

  fmt.Printf("first freespace addr is at: 0x%0x\n", addr)

  // we're essentially defining the function:
  //   void* fqn(size_t n) {
  //     void* mem = NULL;
  //     posix_memalign(&mem, 4096, n);
  //     return mem;
  //   }
  // but in pure object code.  Note that the above relies on posix_memalign not
  // changing 'mem' when it fails, which isn't necessarily guaranteed... 
  memalign_code := []byte{
    0x48, 0x83, 0xec, 0x18,                   // sub    $0x18,%rsp
    0x48, 0x89, 0xfa,                         // mov    %rdi,%rdx
    0xbe, 0x00, 0x10, 0x00, 0x00,             // mov    $0x1000,%esi
    0x48, 0x89, 0xe7,                         // mov    %rsp,%rdi
    0x48, 0xc7, 0x04, 0x24,                   // movq   $0x0,(%rsp)
      0x00, 0x00, 0x00, 0x00,                 // (this is the 0x0)
    //0xe8, 0xe4, 0xfe, 0xff, 0xff,           // callq  posix_memalign
    // The FF's are an reloffset; we cannot know it statically.  See below.
    0xe8, 0xFF, 0xFF, 0xFF, 0xFF,             // callq  posix_memalign
    0x48, 0x8b, 0x04, 0x24,                   // mov    (%rsp),%rax
    0x48, 0x83, 0xc4, 0x18,                   // add    $0x18,%rsp
    0xc3,                                     // retq
    0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, // nopw   %cs:0x0(%rax,%rax,1)
    0x00, 0x00, 0x00,
    0x90,                                     // nop
  }

  // Now we have to fix up the 'call' address that is filled with "0xFF" (note
  // caps) above.  We need to fill that 32bit space with the *relative* address
  // of posix_memalign.  It's relative to the instruction pointer, but not the
  // instruction pointer /now/, rather the address of the END of the call
  // instruction (i.e. address of the instruction after the call).
  // Since we're going to fill 'addr' with this function, that can serve as our
  // base address.  Then it's just an issue of counting bytes.
  malign_addr := addr + 23
  malign_end_addr := malign_addr + 5
  malign_reladdr := int64(memalign) - int64(malign_end_addr)
  fmt.Printf("memalign is at: %v (0x%0x)\n", memalign, memalign)
  fmt.Printf("reladdr: %v (0x%0x)\n", malign_reladdr, malign_reladdr)
  if malign_reladdr != int64(int32(malign_reladdr)) { // does it fit in 32bit?
    panic("can't encode jump to posix_memalign as a near call!")
  }

  // 23 bytes in is the 'e8' of our call.  We want to replace the argument,
  // which is 1 past that, and is 4 bytes long.
  // I have no idea why the -4 is needed, but looking at the ouptut, it is.
  replace(memalign_code[23+1:23+1+4], int32(malign_reladdr))

  // This is just for debugging, so we can see if what we put in there is valid.
  fmt.Printf("buf:\n")
  for i,v := range memalign_code {
    if i >= 23+1 && i < 23+1+4 { // the code (address) we are replacing.
      fmt.Printf("0x%02X ", v)
    } else {
      fmt.Printf("0x%02x ", v)
    }
    if i != 0 && (i % 15) == 0 { fmt.Printf("\n") }
  }
  fmt.Printf("\ndecoded:\n")
  for offset := 0 ; offset < len(memalign_code) ; {
    ixn, err := x86asm.Decode(memalign_code[offset:], 64)
    if err != nil { panic(err) }
    fmt.Printf("\t%v\n", ixn)
    offset += ixn.Len
  }

  // .. maybe we should read/save whatever code is already there, first?
  if err = inferior.Write(addr, memalign_code) ; err != nil {
    return 0x0, err
  }

  return addr, nil
  // next: save registers, overwrite current instruction pointer so we
  // 'call $addr', break somewhere inside this function so that we can
  // restore the old instruction pointer's value, finish our function,
  // restore registers except make sure we place our aligned alloc
  // retval into the right place, rock.
}
