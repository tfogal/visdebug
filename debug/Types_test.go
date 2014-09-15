// This debug code is really dependent on the 'dimensional' testprogram; if
// that changes, the addresses here will probably change.
package debug

import "debug/dwarf"
import "fmt"
import "strings"
import "testing"

var program = []string{"../testprograms/dimensional", "3"}

func TestTypeGlobal(t *testing.T) {
  gArr(t, 0x602070)
}
func TestTypeGlobalMidArray(t *testing.T) {
  gArr(t, 0x602078)
}

func TestTypeArg(t *testing.T) {
  typ, err := TypeLocal(program[0], "smooth3", -96)
  if err != nil {
    t.Fatalf("%v", err)
  }
  if typ.Signed() {
    t.Fatalf("%v should be unsigned!", typ)
  }

  btype, err := Basetype(program[0], typ)
  if err != nil {
    t.Fatalf("btype for x0: %v", btype.Type)
  }
  if btype.Signed() {
    t.Fatalf("%v should be unsigned!", btype)
  }
}

type tstlvarinfo struct {
  fqn string
  offset int64
  signed bool
}
var lvtests = []tstlvarinfo{
  {"smooth3", - 80, false},
  {"smooth3", - 88, false},
  {"smooth3", - 96, false},
  {"smooth3", -104, false},
  {"smooth3", -112, true},
  {"smooth3", -120, true},
  {"smooth3", -128, true},
  {"smooth3", -144, true}, // formal parameter, i.e. 'v'
  {"smooth2", - 56, true},
  {"smooth2", - 40, false},
  {"smooth2", - 32, false},
  {"smooth2", - 24, false},
  {"clamp",   - 24, true},
  {"clamp",   - 32, false},
}

func TestTypeArgSmooth3(t *testing.T) {
  for _, lvt := range lvtests {
    typ, err := TypeLocal(program[0], lvt.fqn, lvt.offset)
    if err != nil {
      t.Error("Test", lvt, " had error:", err)
    } else {
      if typ.Signed() != lvt.signed {
        t.Error("Test", lvt, " is not signed, got:", typ)
      }
    }
  }
}

func gArr(t *testing.T, address uintptr) {
  typ, err := TypeGlobalVar(program[0], address)
  if err != nil {
    t.Fatalf("finding type: %v", err)
  }
  _, ok := (typ.Type).(*dwarf.ArrayType)
  if !ok {
    t.Fatalf("could not convert type (%v) to array type: %v", typ.Type, err)
  }
  if !strings.Contains(fmt.Sprintf("%v", typ), "size_t") {
    t.Fatalf("'dims' should be a size_t, not '%v'", typ.Type)
  }

  if typ.Signed() {
    t.Fatalf("%v should be unsigned!", typ)
  }

  btype, err := Basetype(program[0], typ)
  if err != nil {
    t.Fatalf("btype for dims: %v", btype.Type)
  }
  if btype.Signed() {
    t.Fatalf("%v should be unsigned!", btype)
  }
}
