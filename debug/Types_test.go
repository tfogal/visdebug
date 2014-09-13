package debug

import "debug/dwarf"
import "fmt"
import "strings"
import "testing"

var program = []string{"../testprograms/dimensional", "3"}

func TestBasetypeGlobal(t *testing.T) {
  //typ, err := BasetypeGlobal(program[0], 0x602070, dwarf.TagBaseType)
  typ, err := BasetypeGlobal(program[0], 0x602070, dwarf.TagArrayType)
  if err != nil {
    t.Fatalf("finding type: %v", err)
  }
  _, ok := (typ).(*dwarf.ArrayType)
  if !ok {
    t.Fatalf("could not convert type to array type: %v", err)
  }
  if !strings.Contains(fmt.Sprintf("%v", typ), "size_t") {
    t.Fatalf("'dims' should be a size_t, not '%v'", typ)
  }
}
