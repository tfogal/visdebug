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

  addr, err := setup_tjfmalloc(inferior)
  if err != nil {
    t.Fatalf("error inserting our malloc: %v", err)
  }

  if addr < symbol("main", symbols).Address() {
    t.Fatalf("address 0x%0x makes no sense", addr)
  }

  if err := inferior.Continue() ; err != nil {
    t.Fatalf("could not finish program: %v", err)
  }
  <- inferior.Events() // let it finish.
}

// Tests filling memory with the 'unprotect' function.
func TestSetupUnprotect(t *testing.T) {
  argv := []string{"testprograms/dimensional", "3"}
  inferior, err := startup(argv)
  if err != nil {
    t.Fatalf("can't exec child: %v", err)
  }
  defer inferior.Close()

  symbols, err := bfd.SymbolsProcess(inferior)
  if err != nil {
    t.Fatalf("could not read symbols: %v\n", err)
  }

  addr, err := setup_unprotect(inferior)
  if err != nil {
    t.Fatalf("could not define 'unprotect' function: %v", err)
  }

  if addr < symbol("main", symbols).Address() {
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

  addr, err := setup_tjfmalloc(inferior)
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

  fmt.Printf("mallocing %v bytes but jumping to 0x%0x instead. Ret to: 0x%0x\n",
             nbytes, addr, retsite)
  // now, instead, "jump" to our 'new' function.
  if err := inferior.SetIPtr(addr) ; err != nil {
    t.Fatalf("jumping to our in-mem function: %v", err)
  }
  // let our replacement malloc run
  if err := debug.WaitUntil(inferior, retsite) ; err != nil {
    t.Fatalf("never came back from our function? %v", err)
  }
  rval := stack.RetVal(inferior)
  if rval == 0x0 {
    t.Fatalf("retval should not be null!")
  }

  // insns_stdout(inferior)
  if err := inferior.Continue() ; err != nil {
    t.Fatalf("could not continue: %v", err)
  }
  <- inferior.Events() // let it go.
}
