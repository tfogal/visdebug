package main
import "fmt"
import "testing"
import "./bfd"
import "./debug"
import "github.com/tfogal/ptrace"

func startup(argv []string) (*ptrace.Tracee, error) {
  inferior, err := ptrace.Exec(argv[0], argv)
  if err != nil {
    return nil, err
  }
  <- inferior.Events() // eat 'process is starting' event.

  if err := MainSync(argv[0], inferior) ; err != nil {
    inferior.Close()
    return nil, err
  }
  return inferior, nil
}

func TestAllocInferior(t *testing.T) {
  argv := []string{"testprograms/dimensional", "3"}
  inferior, err := startup(argv)
  if err != nil {
    t.Fatalf("can't exec child: %v", err)
  }
  defer inferior.Close()

  symbols, err := bfd.SymbolsProcess(inferior)
  if err != nil {
    t.Fatalf("could not read smbols: %v\n", err)
  }

  malign := symbol("posix_memalign", symbols)
  if malign == nil {
    t.Fatalf("no posix_memalign symbol")
  }

  malloc := symbol("malloc", symbols)
  if malloc == nil || malloc.Address() == 0x0 {
    t.Fatalf("malloc symbol not available, symbtab broken?")
  }

  mmap := symbol("mmap", symbols)
  if mmap == nil {
    t.Fatalf("no mmap!")
  }
  main := symbol("main", symbols)
  if main == nil {
    t.Fatalf("no main!")
  }

  addr, err := alloc_inferior(inferior, mmap.Address(), main.Address())
  if err != nil {
    t.Fatalf("creating memory for our memalign: %v", err)
  }
  if addr < main.Address() {
    t.Fatalf("address 0x%0x makes no sense", addr)
  }

  if err := inferior.Continue() ; err != nil {
    t.Fatalf("could not finish program: %v", err)
  }
  <- inferior.Events() // let it finish.
}

func TestExecFill(t *testing.T) {
  argv := []string{"testprograms/dimensional", "3"}
  inferior, err := startup(argv)
  if err != nil {
    t.Fatalf("startup failed: %v", err)
  }
  defer inferior.Close()

  symbols, err := bfd.SymbolsProcess(inferior)
  if err != nil {
    t.Fatalf("could not read smbols: %v\n", err)
  }

  malign := symbol("posix_memalign", symbols)
  if malign == nil {
    t.Fatalf("no posix_memalign symbol")
  }
  mmap := symbol("mmap", symbols)
  if mmap == nil {
    t.Fatalf("no mmap!")
  }
  main := symbol("main", symbols)
  if main == nil {
    t.Fatalf("no main!")
  }

  addr, err := alloc_inferior(inferior, mmap.Address(), main.Address())
  if err != nil {
    t.Fatalf("error allocating mem in inferior: %v", err)
  }

  _, err = fspace_fill(inferior, addr, malign.Address())
  if err != nil {
    t.Fatalf("error inserting our malloc: %v", err)
  }

  malloc := symbol("malloc", symbols)
  if malloc == nil || malloc.Address() == 0x0 {
    t.Fatalf("malloc symbol not available, symbtab broken?")
  }
  if err := debug.WaitUntil(inferior, malloc.Address()) ; err != nil {
    t.Fatalf("never hit a malloc? %v", err)
  }

  var stack x86_64
  // save the return address so we know where to go back to.
  retsite := stack.RetAddr(inferior)
  nbytes := stack.Arg1(inferior)

  orig_regs, err := inferior.GetRegs()
  if err != nil {
    t.Fatalf("could not grab regs: %v", err)
  }
  fmt.Printf("mallocing %v bytes but jumping to 0x%0x instead. Ret to: 0x%0x\n",
             nbytes, addr, retsite)
  fmt.Printf("rip: 0x%0x\n", orig_regs.Rip)
  // now, instead, "jump" to our 'new' function.
  if err := inferior.SetIPtr(addr) ; err != nil {
    t.Fatalf("jumping to our in-mem function: %v", err)
  }
  // let our replacement malloc run
  if err := debug.WaitUntil(inferior, retsite) ; err != nil {
    t.Fatalf("never came back from our function? %v", err)
  }
  rval := stack.RetVal(inferior)
  fmt.Printf("retval is: 0x%0x\n", rval)

  // insns_stdout(inferior)
  if err := inferior.Continue() ; err != nil {
    t.Fatalf("could not continue: %v", err)
  }
  <- inferior.Events() // let it go.
}
