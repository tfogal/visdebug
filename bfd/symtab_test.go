package bfd

import "testing"

func TestReadSymbols(t *testing.T) {
  descriptor, err := OpenR("../testprograms/dimensional", "")
  if err != nil {
    t.Fatalf("error opening bfd: %v\n", err)
  }
  symbols := Symbols(descriptor)

  if err := Close(descriptor) ; err != nil {
    t.Fatalf("could not close bfd file: %v\n", err)
  }
  if len(symbols) < 20 {
    t.Fatalf("symbol reading broken?  only read %d symbols.", len(symbols))
  }
}

func TestSymbolsProcess(t *testing.T) {
  SymbolsProcess(42);
}
