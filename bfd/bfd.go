package bfd
// #include <stdio.h>
// #include <stdlib.h>
// #include <elf.h>
// #include "syms.h"
// #cgo CFLAGS: -std=gnu99
// #cgo LDFLAGS: -lbfd
import "C"
import "debug/elf"
import "errors"
import "fmt"
import "io/ioutil"
import "os"
import "reflect"
import "sort"
import "strings"
import "unsafe"
import "github.com/tfogal/ptrace"

/* BFD uses these values for defines it reads from. */
const(
  FALSE = 0
  TRUE = 1
);

// enum bfd_format:
const (
  bfd_unknown = 0   /* File format is unknown.  */
  bfd_object = 1    /* Linker/assembler/compiler output.  */
  bfd_archive=2     /* Object archive file.  */
  bfd_core=3    /* Core dump.  */
  bfd_type_end=4    /* Marks the end; don't use it!  */
)

// flags for a BFD file
const(
  bfd_BFD_NO_FLAGS = 0x00
  bfd_HAS_RELOC = 0x01
  bfd_EXEC_P = 0x02
  bfd_HAS_LINENO = 0x04
  bfd_HAS_DEBUG = 0x08
  bfd_HAS_SYMS = 0x10
)
// flags for a symbol
const(
  bfd_BSF_LOCAL = (1 << 0)
  bfd_BSF_GLOBAL = (1 << 1)
  bfd_BSF_EXPORT = bfd_BSF_GLOBAL
  bfd_BSF_DEBUGGING = (1 << 2)
  bfd_BSF_FUNCTION = (1 << 3)
  bfd_BSF_KEEP = (1 << 5)   // used by the linker
  bfd_BSF_KEEP_G = (1 << 6) //         ""
  bfd_BSF_WEAK = (1 << 7)
  bfd_BSF_SECTION_SYM = (1 << 8) // pointer to section symbol
  bfd_BSF_OLD_COMMON = (1 << 9) // was common, but now allocated.
  bfd_BSF_NOT_AT_END = (1 << 10) // long explanation; see docs.
  bfd_BSF_CONSTRUCTOR = (1 << 11) // symbol starts constructor section
  bfd_BSF_WARNING = (1 << 12) // cur. symbol is warning about next symbol
  bfd_BSF_INDIRECT = (1 << 13) // indirect symbol
  bfd_BSF_FILE = (1 << 14) // symbol is a file name.
  bfd_BSF_DYNAMIC = (1 << 15) // dynamic linking information
  bfd_BSF_OBJECT = (1 << 16) // symbol is a "data object"
  bfd_BSF_DEBUGGING_RELOC = (1 << 17) // debugging relocation
  bfd_BSF_THREAD_LOCAL = (1 << 18) // TLS symbol
  bfd_BSF_RELC = (1 << 19) // complex relocation (what?)
  bfd_BSF_SRELC = (1 << 20) // signed complex relocation
  bfd_BSF_SYNTHETIC = (1 << 21) // see docs.
  bfd_BSF_GNU_INDIRECT_FUNCTION = (1 << 2) // call fqn to compute sym value
  bfd_BSF_GNU_UNIQUE = (1 << 23) // globally unique symbol
)

type Symbol struct {
  name string
  addr uintptr
  flags uint
}
func (s *Symbol) Name() (string) { return s.name }
func (s *Symbol) Address() (uintptr) { return s.addr }
func (s *Symbol) Local() (bool) { return (s.flags & bfd_BSF_LOCAL) > 0; }
func (s *Symbol) Global() (bool) { return (s.flags & bfd_BSF_GLOBAL) > 0; }
func (s *Symbol) Exported() (bool) { return (s.flags & bfd_BSF_EXPORT) > 0; }
func (s *Symbol) Debug() (bool) { return (s.flags & bfd_BSF_DEBUGGING) > 0; }
func (s *Symbol) Function() (bool) { return (s.flags & bfd_BSF_FUNCTION) > 0; }
func (s *Symbol) Keep() (bool) { return (s.flags & bfd_BSF_KEEP) > 0; }
func (s *Symbol) KeepG() (bool) { return (s.flags & bfd_BSF_KEEP_G) > 0; }
func (s *Symbol) Weak() (bool) { return (s.flags & bfd_BSF_WEAK) > 0; }
func (s *Symbol) Section() (bool) {
  return (s.flags & bfd_BSF_SECTION_SYM) > 0;
}
func (s *Symbol) OldCommon() (bool) {
  return (s.flags & bfd_BSF_OLD_COMMON) > 0;
}
func (s *Symbol) NotEnd() (bool) { return (s.flags & bfd_BSF_NOT_AT_END) > 0; }
func (s *Symbol) Constructor() (bool) {
  return (s.flags & bfd_BSF_CONSTRUCTOR) > 0;
}
func (s *Symbol) Warning() (bool) { return (s.flags & bfd_BSF_WARNING) > 0; }
func (s *Symbol) Indirect() (bool) { return (s.flags & bfd_BSF_INDIRECT) > 0; }
func (s *Symbol) File() (bool) { return (s.flags & bfd_BSF_FILE) > 0; }
func (s *Symbol) Dynamic() (bool) { return (s.flags & bfd_BSF_DYNAMIC) > 0; }
func (s *Symbol) Object() (bool) { return (s.flags & bfd_BSF_OBJECT) > 0; }
func (s *Symbol) DebugRelocation() (bool) {
  return (s.flags & bfd_BSF_DEBUGGING_RELOC) > 0;
}
func (s *Symbol) ThreadLocal() (bool) {
  return (s.flags & bfd_BSF_THREAD_LOCAL) > 0;
}
func (s *Symbol) ComplexRelocation() (bool) {
  return (s.flags & bfd_BSF_RELC) > 0;
}
func (s *Symbol) SignedComplexRelocation() (bool) {
  return (s.flags & bfd_BSF_SRELC) > 0;
}
func (s *Symbol) Synthetic() (bool) {
  return (s.flags & bfd_BSF_SYNTHETIC) > 0;
}
func (s *Symbol) IndirectFunction() (bool) {
  return (s.flags & bfd_BSF_GNU_INDIRECT_FUNCTION) > 0;
}
func (s *Symbol) GloballyUnique() (bool) {
  return (s.flags & bfd_BSF_GNU_UNIQUE) > 0;
}
/* for sorting the symbols */
type SymList []Symbol
func (s SymList) Len() int { return len(s); }
func (s SymList) Less(i int, j int) bool { return s[i].name < s[j].name }
func (s SymList) Swap(i int, j int) { s[i], s[j] = s[j], s[i] }

// Returns the symbols for a binary.  These are only for the binary itself, not
// a running process, so the list is not exhaustive.  It will have PLT entries
// for functions called in other libraries, but those symbols' addresses will
// be nonsense.
func Symbols(executable string) ([]Symbol, error) {
  binary, err := elf.Open(executable)
  if err != nil { return nil, err }
  defer binary.Close()

  syms, err := binary.Symbols()
  if err != nil { return nil, err }

  symbols := make([]Symbol, 0)
  for i,_ := range syms {
    if syms[i].Name == "" { continue } // skip "blank" symbols.
    sbind := elf.ST_BIND(syms[i].Info)
    stype := elf.ST_TYPE(syms[i].Info)

    s := Symbol{name: syms[i].Name,  addr: uintptr(syms[i].Value), flags: 0}
    if sbind == elf.STB_LOCAL { s.flags |= bfd_BSF_LOCAL }
    if sbind == elf.STB_GLOBAL { s.flags |= bfd_BSF_GLOBAL }
    if sbind == elf.STB_WEAK { s.flags |= bfd_BSF_WEAK }
    if stype == elf.STT_FUNC { s.flags |= bfd_BSF_FUNCTION }
    if stype == elf.STT_OBJECT { s.flags |= bfd_BSF_OBJECT }
    symbols = append(symbols, s)
  }

  sort.Sort(SymList(symbols))
  return symbols, nil
}

// easy way to enable/disable debugging prints.
//var strm = os.Stdout
var strm = ioutil.Discard

/* Somewhere inside the _DYNAMIC section of the inferior's memory, we should
 * find a DT_DEBUG symbol.  If there's no debug info at all, then eventually
 * we'll just run off the process' address space and get an errno while
 * reading.  The DT_DEBUG leads us to the link_map structure.
 * @param addr address of the _DYNAMIC symbol in the inferior. */
func lmap_head(inferior *ptrace.Tracee, addr uintptr) uintptr {
  for dynaddr:=addr; true; dynaddr += uintptr(C.Elf64_Dynsz()) {
    tag, err := inferior.ReadWord(dynaddr)
    if err != nil {
      fmt.Fprintf(os.Stderr, "could not read word@0x%0x: %v\n", dynaddr, err)
      panic("could not read dynamic tag from inferior")
      return 0x0
    }
    switch(elf.DynTag(tag)) {
      case elf.DT_NULL: /* not found! */
        panic("DT_DEBUG section not found, cannot find link_map")
        return 0x0
      case elf.DT_DEBUG: {
        fmt.Fprintf(strm, "found the debug tag at 0x%0x\n", dynaddr)
        rdbg, err := inferior.ReadWord(dynaddr+uintptr(C.Elf64_Sxwordsz()))
        if err != nil { panic(err) }
        fmt.Fprintf(strm, "r_debug starts at: 0x%x\n", rdbg)
        /* that gave us the address of the r_debug, but we want the link_map */
        rmapaddr := uintptr(rdbg) + uintptr(C.rmap_offset())
        lmap, err := inferior.ReadWord(rmapaddr)
        if err != nil {
          fmt.Fprintf(os.Stderr, "deref link_map (0x%x) failed: %v\n",
                      rmapaddr, err)
          panic("grabbing link_map")
        }
        return uintptr(lmap)
      }
    }
  }
  return 0x0
}

/* reads the symbols using the C function and then converts it into Go types. */
func read_symbols_file(fp *os.File) ([]Symbol, error) {
  C.setprocfd(C.int(fp.Fd()))
  sym := C.read_symtab_procread()
  if sym == nil {
    return nil, errors.New("could not read symbol table")
  }
  defer C.free_symtable(sym)

  /* again with the indexing issue, see above. */
  var gosymtab []C.symbol
  header := (*reflect.SliceHeader)((unsafe.Pointer(&gosymtab)));
  header.Cap = int(sym.n);
  header.Len = int(sym.n);
  header.Data = uintptr(unsafe.Pointer(sym.bols));

  symbols := make([]Symbol, sym.n);
  for i:=C.size_t(0); i < sym.n; i++ {
    symbols[i].name = C.GoString(gosymtab[i].name)
    symbols[i].addr = uintptr(gosymtab[i].address)
    symbols[i].flags = 0
  }
  sort.Sort(SymList(symbols))

  return symbols, nil
}

func relocate_symbols(symbols []Symbol, offset uintptr) {
  for i, _ := range symbols {
    /* There are some 'special' symbols that must NOT be relocated.  SHN_UNDEF
     * and SHN_ABS ones, for example.  I believe SHN_COMMON symbols should not
     * be relocated either.  However, we did not save the symbol type when we
     * built the table, so we can't do that filtering here.  We're going to let
     * it slide, on the basis that our nefarious purposes do not need to fiddle
     * with such symbols. */
    symbols[i].addr += offset
  }
}

func find_symbol(name string, slist []Symbol) *Symbol {
  for _, sym := range slist {
    if sym.name == name {
      return &sym
    }
  }
  return nil
}

/* When an executable calls a function in a library, that library symbol
 * appears in the executable.  Of course, the linker has no idea where that
 * library symbol will be at runtime, so it gives the symbol an address of 0x0
 * and expects the loader to fix things up.
 * Since *we* are the loader, we need to fix things up.  The second symtable,
 * 'with', should come from the library that actually owns the symbol.  We use
 * that symtable to correct the symbols in 'dest'. */
func fix_symbols(dest []Symbol, with []Symbol) {
  for ds, _ := range dest {
    if dest[ds].addr == 0x0 {
      srch := find_symbol(dest[ds].name, with)
      if srch != nil {
        dest[ds].addr = srch.addr
      }
    }
  }
}

func filter_symbols(sy []Symbol, existing []Symbol) []Symbol {
  var rv []Symbol
  for _, s := range sy {
    if find_symbol(s.name, existing) != nil {
      rv = append(rv, s)
    }
  }
  return rv
}

// there are some symbols, e.g. malloc, that we always need, even if the
// application didn't call them directly.  you might think that every
// application needs malloc, but a fortran application, for example, only calls
// malloc through a shared library
type needed_sym struct {
  fromlibrary string
  symname string
}
var needed = []needed_sym{
  {"libc.so", "malloc"},
  {"libc.so", "calloc"},
  {"libc.so", "free"},
  {"libc.so", "getpagesize"},
  {"libc.so", "posix_memalign"},
}

/* reads symbols from the process, properly relocating them to get their actual
 * address. */
func SymbolsProcess(inferior *ptrace.Tracee) ([]Symbol, error) {
  filename := fmt.Sprintf("/proc/%d/exe", inferior.PID())

  symbols, err := Symbols(filename)
  if err != nil { return nil, err }

  fmt.Fprintf(strm, "read %d symbols.\n", len(symbols))
  dyidx := sort.Search(len(symbols), func(i int) bool {
    return symbols[i].name >= "_DYNAMIC"
  })
  if dyidx > len(symbols) || symbols[dyidx].name != "_DYNAMIC" {
    return nil, errors.New("Could not find _DYNAMIC section.")
  }

  fmt.Fprintf(strm, "reading _DYNAMIC section from 0x%x\n", symbols[dyidx].addr)
  lmap_addr := lmap_head(inferior, symbols[dyidx].addr)
  fmt.Fprintf(strm, "head is at: 0x%x\n", lmap_addr)

  for {
    lmap := C.load_lmap(C.pid_t(inferior.PID()), C.uintptr_t(lmap_addr))
    defer C.free(unsafe.Pointer(lmap))
    libname := C.GoString(lmap.l_name)
    fmt.Fprintf(strm, "Library loaded at 0x%012x, next at %p [%s]\n",
                lmap.l_addr, lmap.l_next, libname)
    lmap_addr = uintptr(C.uintptr(unsafe.Pointer(lmap.l_next))) // next round.

    fp, err := os.Open(libname)
    // skip the 'in memory image only' kind of library.
    if libname == "" || err != nil { continue }
    defer fp.Close()
    libsym, err := read_symbols_file(fp)
    if err != nil { panic(err) }

    fmt.Fprintf(strm, "Read %d symbols from %s, relocating by 0x%x\n",
                len(libsym), libname, lmap.l_addr)

    relocate_symbols(libsym, uintptr(lmap.l_addr))

    // most of the time, unless the symbols already exist in the main
    // executable, we don't care about them.  however, there a few symbols in
    // shared libraries that we really need, regardless of if they are directly
    // used by the application.
    for _, need := range needed {
      if strings.Contains(libname, need.fromlibrary) {
        symb := find_symbol(need.symname, libsym)
        if symb != nil {
          fmt.Fprintf(strm, "Adding %s from %s.\n", symb.Name(), libname)
          symbols = append(symbols, *symb)
        }
      }
    }

    fix_symbols(symbols, libsym)

    if lmap_addr == 0x0 { break }
  }
  /*for i:=0; i < len(symbols); i++ {
    fmt.Printf("\t%30s 0x%12x\n", symbols[i].name, symbols[i].addr)
  }*/
  return symbols, nil
}
