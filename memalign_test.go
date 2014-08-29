package main
import "testing"
import "./bfd"
import "github.com/tfogal/ptrace"

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

  addr, err := fspace_fill(inferior, 0x0, malign.Address())
  if err != nil {
    t.Fatalf("could not create aligned function")
  }
  // It's unreasonable that we'd identify low memory as our target address.
  start := symbol("_start", symbols)
  if start == nil { t.Fatalf("no start?!") }
  if addr < start.Address() {
    t.Fatalf("filled 0x%0x with our function, which is below _start (0x%0x)",
             addr, start.Address())
  }
}
