package debug

import "bytes"
import "debug/dwarf"
import "debug/elf"
import "encoding/binary"
import "fmt"
import "io"
import "strings"

type Type struct {
  offset dwarf.Offset
  Type dwarf.Type
}

func (t Type) Signed() bool {
  return type_signed(t.Type)
}

func type_signed(typ dwarf.Type) bool {
  switch {
  case strings.Contains(typ.String(), "float"),
       strings.Contains(typ.String(), "double"),
       strings.Contains(typ.String(), "int8_t"),
       strings.Contains(typ.String(), "int16_t"),
       strings.Contains(typ.String(), "int32_t"),
       strings.Contains(typ.String(), "int64_t"):
    return true
  case strings.Contains(typ.String(), "size_t"),
       strings.Contains(typ.String(), "uint8_t"),
       strings.Contains(typ.String(), "uint16_t"),
       strings.Contains(typ.String(), "uint32_t"),
       strings.Contains(typ.String(), "uint64_t"),
       strings.Contains(typ.String(), "unsigned"):
    return false
  default:
    panic("unknown type")
  }
}

// A dwarfEntry is an interface that lets us search for entries in the DWARF
// debug information.
type dwarfEntry interface {
  // arg0: the current entry
  // rv0: is arg0 the droids we're looking for?
  // rv1: can the droids be in arg0's subtree?
  Match(*dwarf.Entry) (bool, bool)
}
type dwfFunction struct {
  name string
}
func (df dwfFunction) Match(entry *dwarf.Entry) (bool, bool) {
  if entry.Tag == dwarf.TagSubprogram {
    for _, fld := range entry.Field { // can this just be done with ent.Val.(x)?
      if fld.Attr == dwarf.AttrName && fld.Val.(string) == df.name {
        return true, true
      } else if fld.Attr == dwarf.AttrName {
        // it *is* a function, just not the one we're looking for.
        return false, false
      }
    }
  }
  return false, true
}

type dwfGlobalVar struct {
  addr uintptr
}
func (df dwfGlobalVar) Match(entry *dwarf.Entry) (bool, bool) {
  if entry.Tag == dwarf.TagSubprogram {
    // a global var won't be a child of a function.
    return false, false
  }

  if entry.Tag != dwarf.TagVariable {
    return false, true
  }
  loc, isloc := entry.Val(dwarf.AttrLocation).([]uint8)
  if !isloc { // this happens when the symbol is imported, e.g. libc 'stdin'
    return false, true
  }
  // 0x03 seems to be magic for 'raw address comes next'.  a local variable,
  // for example, would be a DW_OP_fbreg and thus not lead with 0x03.
  if loc[0] != 0x03 {
    return false, true
  }
  // looks like we've actually got something relevant.  Convert that byte
  // array to something we can actually use.
  var addr uint64 // uintptr fails the conversion, despite making more sense
  binary.Read(bytes.NewReader(loc[1:]), binary.LittleEndian, &addr)
  if uintptr(addr) == df.addr {
    return true, true
  }

  return false, true
}

type dwfPrintFuncs struct {}
func (df dwfPrintFuncs) Match(entry *dwarf.Entry) (bool, bool) {
  if entry.Tag == dwarf.TagSubprogram {
    fmt.Printf("func: %s\n", function(entry))
    if function(entry) != "clamp" {
      return false, false
    }
  }
  return false, true
}

type dwfLocal struct {
  fbrel int64 // relative offset from the frame pointer
  fqn string
}
// Returns true if the entry is for the given local variable.
func (df dwfLocal) Match(entry *dwarf.Entry) (bool, bool) {
  if entry.Tag == dwarf.TagSubprogram {
    // if this is a function, but not the one we're looking for, then its whole
    // subtree is junk.  prune it.
    if function(entry) != df.fqn {
//      fmt.Printf("skipping %s because it's not our target of %s\n",
//                 function(entry), df.fqn)
      return false, false
    }
  }

  if entry.Tag != dwarf.TagFormalParameter && entry.Tag != dwarf.TagVariable {
    return false, true
  }

  val, ok := entry.Val(dwarf.AttrLocation).([]uint8)
  if !ok {
    return false, true
  }
  leb := sleb128(val)
  if leb != df.fbrel {
    return false, true
  }
  return true, true
}

func function(entry *dwarf.Entry) string {
  if entry.Tag != dwarf.TagSubprogram {
    panic("probably means you're doing something wrong (why call this?)")
    return ""
  }
  for _, fld := range entry.Field { // can this just be done with ent.Val.(x)?
    if fld.Attr == dwarf.AttrName {
      return fld.Val.(string)
    }
  }
  return ""
}

func searchfor(program string, target dwarfEntry) (*dwarf.Entry, error) {
  legolas, err := elf.Open(program)
  if err != nil {
    return nil, fmt.Errorf("legolas failed us: %v", err)
  }
  gimli, err := legolas.DWARF()
  if err != nil {
    return nil, fmt.Errorf("death by tossing: %v", err)
  }
  rdr := gimli.Reader()

  for ent, err := rdr.Next(); err != io.EOF; ent, err = rdr.Next() {
    if err != nil {
      return nil, err
    }
    if ent == nil { // won't find what we're looking for in other sections.
      break
    }
    matches, relevant := target.Match(ent)
    if matches {
      return ent, nil
    }
    if !relevant {
      rdr.SkipChildren()
    }
  }
  return nil, io.EOF
}

// looks up the dwarf type for the given offset.
func dwftype(program string, offs dwarf.Offset) (dwarf.Type, error) {
  legolas, err := elf.Open(program)
  if err != nil {
    return nil, err
  }
  defer legolas.Close()

  gimli, err := legolas.DWARF()
  if err != nil {
    return nil, err
  }

  ty, err := gimli.Type(offs)
  if err != nil {
    return nil, err
  }

  return ty, nil
}

// identifies the type of a global variable, as given by its address.
func TypeGlobalVar(program string, address uintptr) (Type, error) {
  var ent *dwarf.Entry
  var err error

  // For array accesses, we'll see the address of the access, not of the base
  // of the array.  However (of course), only the base address appears in the
  // debug information.
  // So, we take the approach of: search for the address the user gives us.  If
  // we don't find anything, drop the address down and search again.  Continue
  // doing this until we find *something*, then check if the something we found
  // extends beyond the access address we're looking for.
  for addr := address; ent == nil && addr > 0x400000; addr -= 0x1 {
    ent, err = searchfor(program, dwfGlobalVar{addr: addr})
    if err == io.EOF {
      continue
    }
    if err != nil {
      return Type{}, err
    }

    offs, ok := ent.Val(dwarf.AttrType).(dwarf.Offset)
    if !ok {
      return Type{}, fmt.Errorf("address 0x%0x has no offset, not global var?",
                                address)
    }

    ty, err := dwftype(program, offs)
    if err != nil {
      return Type{}, err
    }
    if addr != address {
      /*
      fmt.Printf("did not find at original place. 0x%0x instead of 0x%0x\n",
                 addr, address)
      fmt.Printf("length is: %d, meaning 0x%0x extends to 0x%0x\n", ty.Size(),
                 addr, addr+uintptr(ty.Size()))
      */
      if addr+uintptr(ty.Size()) < address { // then it wasn't found.
        return Type{}, io.EOF
      }
    }
    return Type{offset: offs, Type: ty}, nil
  }
  return Type{}, fmt.Errorf("impossible")
}

// identifies a local (parameter or local variable), described by a (fqn,
// offset-off-of-fptr) pair.
func TypeLocal(program string, fqn string, rel int64) (Type, error) {
  entry, err := searchfor(program, dwfLocal{fbrel: rel, fqn: fqn})
  if err != nil {
    return Type{}, err
  }

  offs, ok := entry.Val(dwarf.AttrType).(dwarf.Offset)
  if !ok {
    return Type{}, fmt.Errorf("(%s,%d) has no offset.. not a local?", fqn, rel)
  }

  ty, err := dwftype(program, offs)
  if err != nil {
    return Type{}, err
  }

  /*
  name, ok := entry.Val(dwarf.AttrName).(string) // del this when FIN'd dbging
  if ok {
    fmt.Printf("found %s (%d): %v\n", name, rel, ty)
  }
  */

  return Type{offset: offs, Type: ty}, nil
}

func Basetype(program string, typ Type) (Type, error) {
  legolas, err := elf.Open(program)
  if err != nil {
    return Type{}, err
  }
  defer legolas.Close()

  gimli, err := legolas.DWARF()
  if err != nil {
    return Type{}, err
  }

  return basetype(gimli, typ)
}

func basetype(gimli *dwarf.Data, typ Type) (Type, error) {
  rdr := gimli.Reader()

  rdr.Seek(typ.offset)
  ent, err := rdr.Next()
  if err != nil {
    return Type{}, err
  }

  if ent.Tag == dwarf.TagBaseType {
    btype, err := gimli.Type(ent.Offset)
    if err != nil {
      return Type{}, err
    }
    return Type{offset: ent.Offset, Type: btype}, nil
  }
  offs, ok := ent.Val(dwarf.AttrType).(dwarf.Offset)
  if !ok {
    return Type{}, fmt.Errorf("type chain ended before we found basetype")
  }
  return basetype(gimli, Type{offset: offs, Type: typ.Type})
}
