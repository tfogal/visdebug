package main
import "testing"

func init() {
  globals = CmdGlobal{"testprograms/dimensional"}
}

func TestDimsType(t *testing.T) {
  d, err := dbg_gvar_basetype(globals.program, 0x602070)
  if err != nil {
    t.Fatalf("func failed: %v\n", err)
  }
  dims := d.Common()
  if dims.ByteSize != 8 {
    t.Fatalf("byte size %v instead of 8\n", dims.ByteSize)
  }
  if dims.Name != "long unsigned int" { // aka size_t
    t.Fatalf("base type not 'long unsigned int': %v\n", dims.Name)
  }
}
