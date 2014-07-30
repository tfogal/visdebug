package debug
import "sort"
import "testing"
import "github.com/tfogal/ptrace"
import "../bfd"

func TestBreak(t *testing.T) {
  argv := []string{"../testprograms/dimensional", "3"}
  syms, err := bfd.Symbols(argv[0])

  if syms == nil {
    t.Fatalf("could not read symbols so can't do our test: %v\n", err)
  }
  imain := sort.Search(len(syms), func (i int) bool {
    return syms[i].Name() >= "main"
  })
  if imain == len(syms) {
    t.Fatalf("'main' not found; is this an executable?  can't run test.\n")
  }
  if syms[imain].Address() == 0x0 {
    t.Fatalf("main's address is garbage.. something is wrong.\n")
  }

  inferior, err := ptrace.Exec(argv[0], argv)
  if err != nil {
    t.Fatalf("ptrace is broken, can't do our tests: %v\n", err)
  }
  <- inferior.Events()
  defer inferior.Close()

  bp, err := Break(inferior, syms[imain].Address())
  if err != nil {
    t.Fatalf("could not set breakpoint: %v\n", err)
  }
  if err := Unbreak(inferior, bp) ; err != nil {
    t.Fatalf("cannot unset breakpoint: %v\n", err)
  }
}
