package bfd
// #include <stdio.h>
// #include <stdlib.h>
// #include <bfd.h>
// #include <elf.h>
// #include "wrapbfd.h"
// #include "syms.h"
// #cgo CFLAGS: -std=gnu99
// #cgo LDFLAGS: -lbfd
import "C"
import "debug/elf"
import "errors"
import "fmt"
import "os"
import "reflect"
import "strings"
import "sort"
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

/* Open a BFD file read-only.  Use a target string of "" for a null pointer.
 * Returned memory must eventually be passed to Close. */
func OpenR(filename string, target string) (*C.bfd, error) {
  var cfilename *_Ctype_char;
  cfilename = C.CString(filename);
  ctarget := C.CString(target);
  defer C.free(unsafe.Pointer(cfilename));
  if target == "" {
    C.free(unsafe.Pointer(ctarget));
    ctarget = nil;
  }
  defer C.free(unsafe.Pointer(ctarget));


  bfd := C.bfd_openr(cfilename, ctarget);
  if bfd == nil {
    return bfd, errors.New("could not open file")
  }

  err := C.bfd_check_format(bfd, bfd_archive);
  /* confusingly, that doesn't return normal TRUE/FALSE error conditions. */
  if err == 1 {
    Close(bfd);
    return nil, errors.New("(BFD) invalid format");
  }

  /* if we don't do this, later calls that actually read things on the BFD will
   * segfault. */
  err = C.bfd_check_format_matches(bfd, bfd_object, nil);
  if err == FALSE {
    Close(bfd);
    // Two points for honesty.
    return nil, errors.New("(BFD) i honestly do not know.");
  }

  return bfd, nil;
}

func Close(bfd *C.bfd) (error) {
  rv := C.bfd_close(bfd);
  if rv == FALSE {
    return errors.New("unknown error closing BFD");
  }
  return nil;
}

func Symbols(bfd *C.bfd) ([]Symbol) {
  flags := bfd.flags;
  if flags & bfd_HAS_SYMS == 0 {
    return nil;
  }
  var nsymbols C.unsigned;
  symtab := C.readsyms(bfd, &nsymbols);
  if symtab == nil {
    panic("binary has symbols but no symbols given when read!")
  }

  /* Go won't let us index our 'symtab'.  So hack it into a go slice first */
  var gosymtab []*C.asymbol;
  header := (*reflect.SliceHeader)((unsafe.Pointer(&gosymtab)));
  header.Cap = int(nsymbols);
  header.Len = int(nsymbols);
  header.Data = uintptr(unsafe.Pointer(symtab));

  // now construct our return value: a slice of symbols.
  symbols := make([]Symbol, nsymbols);
  for i:=uint(0); i < uint(nsymbols); i++ {
    symbols[i].name = C.GoString(gosymtab[i].name)
    symbols[i].flags = uint(gosymtab[i].flags);

    // the address we get from gosymtab[i].udata[:] is often null, and doesn't
    // match up with 'nm' gives.  Not really sure what it is, yet, but
    // 'bfd_symbol_info' seems to give back addresses that agree with 'nm'.
    var info C.symbol_info;
    C.bfd_symbol_info(gosymtab[i], &info);
    symbols[i].addr = uintptr(info.value);
  }

  C.free(unsafe.Pointer(symtab));
  return symbols;
}

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
        fmt.Printf("found the debug tag at 0x%0x\n", dynaddr)
        rdbg, err := inferior.ReadWord(dynaddr+uintptr(C.Elf64_Sxwordsz()))
        if err != nil { panic(err) }
        fmt.Printf("r_debug starts at: 0x%x\n", rdbg)
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

/* reads symbols from the process, properly relocating them to get their actual
 * address. */
func SymbolsProcess(inferior *ptrace.Tracee) ([]Symbol, error) {
  filename := fmt.Sprintf("/proc/%d/exe", inferior.PID())
  file, err := os.Open(filename)
  if err != nil { return nil, err }
  defer file.Close()

  symbols, err := read_symbols_file(file)
  if err != nil { return nil, err }

  fmt.Printf("read %d symbols.\n", len(symbols))
  dyidx := sort.Search(len(symbols), func(i int) bool {
    return symbols[i].name >= "_DYNAMIC"
  })
  if dyidx > len(symbols) || symbols[dyidx].name != "_DYNAMIC" {
    return nil, errors.New("Could not find _DYNAMIC section.")
  }

  fmt.Printf("reading the _DYNAMIC section from 0x%0x\n", symbols[dyidx].addr)
  lmap_addr := lmap_head(inferior, symbols[dyidx].addr)
  fmt.Printf("head is at: 0x%x\n", lmap_addr)

  for {
    lmap := C.load_lmap(C.pid_t(inferior.PID()), C.uintptr_t(lmap_addr))
    defer C.free(unsafe.Pointer(lmap))
    libname := C.GoString(lmap.l_name)
    fmt.Printf("Library loaded at 0x%012x, next at %p [%s]\n",
               lmap.l_addr, lmap.l_next, libname)
    lmap_addr = uintptr(C.uintptr(unsafe.Pointer(lmap.l_next))) // next round.

    fp, err := os.Open(libname)
    defer fp.Close()
    // Open will fail if we have a null filename.
    if err == nil && strings.Contains(libname, "ld-linux-x86-64") {
      libsym, err := read_symbols_file(fp)
      if err != nil { return nil, err }
      fmt.Printf("relocating %d symbols by 0x%x\n", len(libsym), lmap.l_addr)
      relocate_symbols(libsym, uintptr(lmap.l_addr))
      fix_symbols(symbols, libsym)
    }

    if lmap_addr == 0x0 { break }
  }

  { sympause := find_symbol("pause", symbols)
    if sympause != nil {
      fmt.Printf("%10s@0x%0x\n", "pause", sympause.addr)
    }
  }
  { symmalloc := find_symbol("malloc", symbols)
    if symmalloc != nil {
      fmt.Printf("%10s@0x%0x\n", "malloc", symmalloc.addr)
    }
  }
  { symfree := find_symbol("free", symbols)
    if symfree != nil {
      fmt.Printf("%10s@0x%0x\n", "free", symfree.addr)
    }
  }
  { symcalloc := find_symbol("calloc", symbols)
    if symcalloc != nil {
      fmt.Printf("%10s@0x%0x\n", "calloc", symcalloc.addr)
    }
  }
  /*for i:=0; i < len(symbols); i++ {
    fmt.Printf("\t%30s 0x%12x\n", symbols[i].name, symbols[i].addr)
  }*/
  return symbols, nil
}
