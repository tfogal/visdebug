package main
import "fmt"
import "testing"
import "./bfd"
import "./debug"
import "github.com/tfogal/ptrace"
import "code.google.com/p/rsc.x86/x86asm"

func TestFill(t *testing.T) {
  argv := []string{"testprograms/dimensional"}
  inferior, err := ptrace.Exec(argv[0], argv)
  if err != nil {
    t.Fatalf("can't exec child: %v", err)
  }
  <- inferior.Events() // eat 'process is starting' event.
  defer inferior.Close()

  if err := MainSync(argv[0], inferior) ; err != nil {
    t.Fatalf("could not sync main: %v", err)
  }

  symbols, err := bfd.SymbolsProcess(inferior)
  if err != nil {
    t.Fatalf("could not read smbols: %v\n", err)
  }

  malign := symbol("posix_memalign", symbols)
  if malign == nil {
    t.Fatalf("no posix_memalign symbol")
  }

  addrs, err := fspace_fill(inferior, 0x0, malign.Address())
  if err != nil {
    t.Fatalf("could not create aligned function")
  }
  // It's unreasonable that we'd identify low memory as our target address.
  start := symbol("_start", symbols)
  if start == nil { t.Fatalf("no start?!") }
  if addrs[0] < start.Address() {
    t.Fatalf("filled 0x%0x with our function, which is below _start (0x%0x)",
             addrs[0], start.Address())
  }
  if addrs[0] >= addrs[1] {
    t.Fatalf("function addresses make no sense, starts after it ends.")
  }
}

func TestExecFill(t *testing.T) {
  argv := []string{"testprograms/dimensional", "3"}
  inferior, err := ptrace.Exec(argv[0], argv)
  if err != nil {
    t.Fatalf("can't exec child: %v", err)
  }
  <- inferior.Events() // eat 'process is starting' event.
  defer inferior.Close()

  if err := MainSync(argv[0], inferior) ; err != nil {
    t.Fatalf("could not sync main: %v", err)
  }

  symbols, err := bfd.SymbolsProcess(inferior)
  if err != nil {
    t.Fatalf("could not read smbols: %v\n", err)
  }

  malign := symbol("posix_memalign", symbols)
  if malign == nil {
    t.Fatalf("no posix_memalign symbol")
  }

  addr, err := fspace_fill(inferior, 0x0, malign.Address())
  if err != nil {
    t.Fatalf("could not create aligned function")
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

  fmt.Printf("start of malloc for %v bytes should return to 0x%0x\n", nbytes,
             retsite)

  // now "jump" to our function and wait until it's done.
  if err := inferior.SetIPtr(addr[0]) ; err != nil {
    t.Fatalf("could not jump to our new code: %v", err)
  }
  fmt.Printf("function ranges from 0x%0x--0x%0x\n", addr[0], addr[1])

  for offset := uintptr(0) ; offset < 64 ; {
    insn := make([]byte, 16)
    if err := inferior.Read(malloc.Address()+offset, insn) ; err != nil {
      t.Fatalf("cant read inferior mem: %v", err)
    }
    ixn, err := x86asm.Decode(insn, 64)
    if err != nil { t.Fatalf("decode: %v", err) }
    fmt.Printf("\t%v\n", ixn)
    offset += uintptr(ixn.Len)
  }

  if err := debug.WaitUntil(inferior, addr[1]) ; err != nil {
    t.Fatalf("never exited our custom code.. %v", err)
  }
}
