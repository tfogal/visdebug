package debug

import "bytes"
import "debug/dwarf"
import "debug/elf"
import "encoding/binary"
import "fmt"
import "io"

// identifies the base type of a global variable.
func BasetypeGlobal(program string, address uintptr,
                    tag dwarf.Tag) (dwarf.Type, error) {
  legolas, err := elf.Open(program)
  if err != nil {
    return nil, err
  }
  defer legolas.Close()

  gimli, err := legolas.DWARF()
  if err != nil {
    return nil, err
  }
  rdr := gimli.Reader()

  for ent, err := rdr.Next(); ent != nil && err != io.EOF;
      ent, err = rdr.Next() {
    if err != nil {
      return nil, err
    }
    if ent.Tag != dwarf.TagVariable { // not the droids we're looking for
      continue
    }
    loc, ok := ent.Val(dwarf.AttrLocation).([]uint8)
    if !ok { // then this is an imported symbol, e.g. libc 'stdin'
      continue
    }
    // 0x03 seems to be magic for 'raw address comes next'.  a local variable,
    // for example, would be FPtr-relative and thus not lead with 0x03.
    if loc[0] != 0x03 {
      continue
    }

    // looks like we've actually got something relevant.  Convert that byte
    // array to something we can actually use.
    var addr uint64 // uintptr fails the conversion, despite making more sense
    binary.Read(bytes.NewReader(loc[1:]), binary.LittleEndian, &addr)
    if uintptr(addr) == address {
      attr, ok := ent.Val(dwarf.AttrType).(dwarf.Offset)
      if !ok {
        return nil, fmt.Errorf("address 0x%0x is not a global var / type",
                               address)
      }
      return follow_typechain(gimli, attr, tag)
    }
  }
  return nil, fmt.Errorf("could not find debug symbol at offset 0x%0x", address)
}

func follow_typechain(gimli *dwarf.Data, offset dwarf.Offset,
                      tag dwarf.Tag) (dwarf.Type, error) {
  rdr := gimli.Reader()
  rdr.Seek(offset)
  ent, err := rdr.Next()
  if err != nil {
    return nil, err
  }

  if ent.Tag == tag {
    typ, err := gimli.Type(ent.Offset)
    if err != nil {
      return nil, err
    }
    return typ, nil
  }
  offs, ok := ent.Val(dwarf.AttrType).(dwarf.Offset)
  if !ok {
    return nil, fmt.Errorf("type chain ended before we found tag %v", tag)
  }
  return follow_typechain(gimli, offs, tag)
}
