/* read symbols from running process. */
/* 1. find _DYNAMIC in normal symtable
 * 2. _Sym's st_value for _DYNAMIC gives d_tag of an Elf64_Dyn in inferior
 * 3. if _Dyn's tag is DT_DEBUG, than +1 word is the _Dyn's d_ptr, PEEK it
 * 4. offsetof(r_debug, r_map) at the d_ptr gives the first link_map
 * 5. iterate through the link_maps to load them. mostly their l_names.
 * 6. foreach link_map's l_name, read symbols from that library (l_name)
 * 7. relocate each symbol by adding link_map's.l_addr into its st_value */
#define _POSIX_C_SOURCE 201212L
#define _LARGEFILE64_SOURCE 1
#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <inttypes.h>
#include <link.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include "syms.h"
#include "wrapbfd.h"
#include "../cfg/compiler.h"

static int linux_read_memory(unsigned long from, unsigned char *to, size_t len,
                             const pid_t pid);

/* returns >0 on success. */
int
read_inferior(void* buf, uintptr_t base, size_t bytes, pid_t inferior) {
  assert(inferior > 0); /* PID must be valid. */
  int rv;
  if((rv = linux_read_memory(base, buf, bytes, inferior)) != 0) {
    char errmsg[512];
    if(strerror_r(errno, errmsg, 512) != 0) {
      perror("error getting error. wow.");
      abort();
    }
    //fprintf(stderr, "error(%d) reading memory: %s\n", errno, errmsg);
  }
  return rv;
}

static bool
valid_header(const Elf64_Ehdr* ehdr) {
  return ehdr->e_ident[0] == 0x7f && ehdr->e_ident[1] == 'E' &&
         ehdr->e_ident[2] == 'L' && ehdr->e_ident[3] == 'F';
}
static bool
valid_pheader(const Elf64_Phdr* phdr) {
  switch(phdr->p_type) {
    case PT_NULL: puts("unused phdr"); break;
    case PT_LOAD: puts("loadable seg"); break;
    case PT_DYNAMIC: puts("dynamic linking tables"); break;
    case PT_INTERP: puts("interp"); break;
    case PT_NOTE: puts("note"); break;
    case PT_SHLIB: puts("shared lib"); break;
    case PT_PHDR: puts("program header table"); break; /* wtf? */
    case PT_LOOS: case PT_HIOS: case PT_LOPROC: case PT_HIPROC:
      puts("env/proc specific"); break;
    default:
      fprintf(stderr, "Unkwown phdr type %d\n", phdr->p_type);
      return false;
  }
  if(phdr->p_flags & PF_X) { puts("ph executable"); }
  if(phdr->p_flags & PF_W) { puts("writable"); }
  if(phdr->p_flags & PF_R) { puts("readable"); }
  return true;
}
static void
print_sec(const Elf64_Shdr hdr) {
  printf("sec hdr: %d, ", hdr.sh_name);
  switch(hdr.sh_type) {
    case SHT_NULL: printf("unused"); break;
    case SHT_PROGBITS: printf("program"); break;
    case SHT_SYMTAB: printf("symbol table"); break;
    case SHT_STRTAB: printf("string table"); break;
    case SHT_RELA: printf("rel 'a' relocations"); break;
    case SHT_HASH: printf("symbol hash table"); break;
    case SHT_DYNAMIC: printf("dynamic linking tables"); break;
    case SHT_NOTE: printf("note info"); break;
    case SHT_NOBITS: printf("uninitialized data"); break;
    case SHT_REL: printf("normal/standard relocations"); break;
    case SHT_SHLIB: printf("'shlib', i.e. reserved"); break;
    case SHT_DYNSYM: printf("dynamic symbol table"); break;
    case SHT_LOOS: case SHT_HIOS: case SHT_LOPROC: case SHT_HIPROC:
      printf("env/proc specific"); break;
  }
  printf("\n");
}
/* addr is the address of the first header */
static void
print_section_headers(const uintptr_t addr, const size_t nhdrs, pid_t pid) {
  printf("printing %zu section headers\n", nhdrs);
  for(size_t i=0; i < nhdrs; ++i) {
    Elf64_Shdr shdr;
    const uintptr_t nxt = addr + i*sizeof(Elf64_Shdr);
    if(read_inferior(&shdr, nxt, sizeof(Elf64_Shdr), pid) != 0) {
      perror("reading sec hdr");
      return;
    }
    print_sec(shdr);
  }
}

uintptr_t
whereami(pid_t inferior) {
  struct user_regs_struct regs;
  if(ptrace(PTRACE_GETREGS, inferior, 0, &regs) != 0) {
    perror("getting registers");
    return 0x0;
  }
  return regs.rip;
}

/** @param dynsection address of the dynamic section */
MALLOC static Elf64_Dyn*
find_got(pid_t inferior, const uintptr_t dynsection) {
  Elf64_Dyn* dyn = malloc(sizeof(Elf64_Dyn));
  dyn->d_tag = -1;
  _Static_assert(-1 != DT_NULL, "loop will not work, otherwise");
  for(size_t i=0; dyn->d_tag != DT_NULL; ++i) {
    const size_t dsz = sizeof(Elf64_Dyn);
    if(read_inferior(dyn, dynsection+i*dsz, dsz, inferior)) {
      perror("reading Elf64_Dyn from inferior.");
      free(dyn);
      return NULL;
    }
    if(dyn->d_tag == DT_PLTGOT) {
      return dyn;
    }
  }
  free(dyn);
  return NULL;
}

static void
section_names(pid_t inferior, const uintptr_t startsec) {
  Elf64_Dyn* dyn = malloc(sizeof(Elf64_Dyn));
  dyn->d_tag = -1;
  _Static_assert(-1 != DT_NULL, "loop will not work, otherwise");
  for(size_t i=0; dyn->d_tag != DT_NULL; ++i) {
    const size_t dsz = sizeof(Elf64_Dyn);
    if(read_inferior(dyn, startsec+i*dsz, dsz, inferior)) {
      fprintf(stderr, "error reading Elf64_Dyn at iter %zu: %d\n", i, errno);
      free(dyn);
      return;
    }
    printf("dynamic %zu: ", i);
    switch(dyn->d_tag) {
      case DT_NULL: puts("end."); break;
      case DT_NEEDED: puts("needed."); break;
      case DT_PLTRELSZ: puts("plt relative sz"); break;
      case DT_PLTGOT:
        printf("PLT GOT address: 0x%0lx\n", dyn->d_un.d_ptr);
        break;
      case DT_HASH: puts("addr of symbol hash table"); break;
      case DT_STRTAB: puts("addr of dynamic string table"); break;
      case DT_SYMTAB: puts("addr of dynamic symtab"); break;
      case DT_RELA: puts("addr of relocA table"); break;
      case DT_RELASZ: puts("size (bytes) of DT_RELA table."); break;
      case DT_RELAENT: puts("size (bytes) per DT_RELA entry"); break;
      case DT_STRSZ: puts("size (bytes) of string table"); break;
      case DT_SYMENT: puts("size (bytes) per symtab entry"); break;
      case DT_INIT: puts("addr of init function"); break;
      case DT_FINI: puts("addr of termination function"); break;
      case DT_SONAME: puts("string table offset of (this) .so name"); break;
      case DT_RPATH: puts("string table offset of rpath"); break;
      case DT_SYMBOLIC: puts("symbolic [ignored!]"); break;
      case DT_REL: puts("addr of reloc table"); break;
      case DT_RELSZ: puts("size (bytes) of reloc table"); break;
      case DT_RELENT: puts("size(bytes) of each reloc entry"); break;
      case DT_PLTREL: puts("type of reloc for proc linkage table (should be "
                           "DT_REL or DT_RELA)"); break;
      case DT_DEBUG:
        puts("reserved for debugger."); break;
      case DT_TEXTREL: puts("reloc table has relocs for RO segment"); break;
      case DT_JMPREL: puts("addr of relocs for PLT"); break;
      case DT_BIND_NOW: puts("early binds"); break;
      case DT_INIT_ARRAY: puts("init array"); break;
      case DT_FINI_ARRAY: puts("finish array"); break;
      case DT_INIT_ARRAYSZ: puts("init array size(bytes)"); break;
      case DT_FINI_ARRAYSZ: puts("finish array size (bytes)"); break;
      default: printf("unknown (0x%x)\n", (int)dyn->d_tag); break;
    }
  }
  free(dyn);
}

static void
read_process_bfd(const char* fn, pid_t chld) {
  bfd* template = bfd_openr(fn, NULL);
  if(template == NULL) {
    fprintf(stderr, "could not create template BFD\n");
    return;
  }
  bfd* lib = bfd_from_inferior(template, 0x0, chld);
  if(lib == NULL) {
    fprintf(stderr, "error creating BFD from inferior.\n");
    if(bfd_close(template) == FALSE) {
      fprintf(stderr, "error closing template BFD...\n");
    }
    return;
  }
  if(bfd_close(lib) == FALSE) {
    fprintf(stderr, "error closing from-memory BFD\n");
  }
  if(bfd_close(template) == FALSE) {
    fprintf(stderr, "error closing template BFD...\n");
  }
}


long procread(void* into, size_t n, size_t offset);

typedef long(rdinf)(void* into, size_t n, size_t offset);
symtable_t* read_symtab(rdinf* rd);

/* Copy LEN bytes from inferior's memory starting at MEMADDR
   to debugger memory starting at MYADDR.  */
typedef long PTRACE_XFER_TYPE;
typedef unsigned long CORE_ADDR;
static int
linux_read_memory(unsigned long memaddr, unsigned char *myaddr, size_t len,
                  const pid_t pid) {
  assert(memaddr > 0x0);
  unsigned long addr;
  int ret;

  /*goto no_proc;*/
  /* Try using /proc first. */
  ssize_t bytes;

  /* We could keep this file open and cache it - possibly one per
     thread.  That requires some juggling, but is even faster.  */
  char filename[64];
  snprintf(filename, 64, "/proc/%d/mem", (int)pid);
  int fd = open(filename, O_RDONLY | O_LARGEFILE);
  if(fd == -1) {
    /*fprintf(stderr, "no memory map.  falling back on ptrace method\n");*/
    goto no_proc;
  }

  errno=0;
  bytes = pread(fd, myaddr, len, memaddr);
  if(bytes < 0) {
    perror("pread64");
    return errno;
  }
  if((size_t)bytes == len) {
    return 0;
  }

  /* Some data was read, we'll try to get the rest with ptrace.  */
  if(bytes > 0) {
    fprintf(stderr, "partial read, trying with ptrace now.\n");
    memaddr += bytes;
    myaddr += bytes;
    len -= bytes;
  }

  no_proc:
  /* Round starting address down to longword boundary.  */
  addr = memaddr & -(unsigned long) sizeof (PTRACE_XFER_TYPE);
  /* Round ending address up; get number of longwords that makes.  */
  const size_t count = (((memaddr + len) - addr) + sizeof(long) - 1) /
                       sizeof (PTRACE_XFER_TYPE);
  /* Allocate buffer of that many longwords.  */
  long *buffer = (PTRACE_XFER_TYPE*)alloca(count * sizeof (PTRACE_XFER_TYPE));
  int err = posix_memalign((void**)&buffer, 64, count*sizeof(PTRACE_XFER_TYPE));
  if(err != 0) {
    fprintf(stderr, "memalign err: %d\n", err);
    return err;
  }
  memset(buffer, 0, count*sizeof(PTRACE_XFER_TYPE));

  /* Read all the longwords */
  errno = 0;
  size_t i;
  for (i = 0; i < count; i++, addr += sizeof (PTRACE_XFER_TYPE)) {
      buffer[i] = ptrace(PTRACE_PEEKTEXT, pid, (uintptr_t) addr, 0);
      if(errno) {
        /*fprintf(stderr, "ptrace read mem error at iter %zu\n", i);*/
        break;
      }
  }
  ret = errno;

  /* Copy appropriate bytes out of the buffer.  */
  if(i > 0) {
    i *= sizeof (PTRACE_XFER_TYPE);
    i -= memaddr & (sizeof (PTRACE_XFER_TYPE) - 1);
    memcpy(myaddr, (char*)buffer + (memaddr & (sizeof(PTRACE_XFER_TYPE) - 1)),
           i < len ? i : len);
  }

  free(buffer);
  return ret;
}

typedef struct _strtable {
  /* It is common for an ELF file to have multiple string tables.  The symbols
   * which refer to the string table do so by the section index of the table
   * that houses the strings---this is how we differentiate them. */
  size_t secidx;
  char* strings;
} strtable_t;

/* function which reads from the inferior.  we use this so we can abstract out
 * reading from a /proc file and ptrace PEEKing.  Always returns the number of
 * bytes read. */
typedef long(rdinf)(void* into, size_t n, size_t offset);
static int procfd = -1;
void setprocfd(int x) { procfd = x; }
long
procread(void* into, size_t n, size_t offset) {
  if(procfd == -1) { return -EINVAL; }
  _Static_assert(sizeof(ssize_t) <= sizeof(long), "Might not be valid anyway,"
                 "but cast is definitely broken if long is too small.");
  return (long)pread(procfd, into, n, offset);
}
/* Reads from the inferior's memory.  The offset is relative: we compensate for
 * the load address of the binary automatically */
static pid_t inferior_pid = -1;
void setinferiorpid(pid_t p) { inferior_pid = p; }
static long
ptraceread(void* into, size_t n, size_t offset) {
#ifdef _LP64
  _Static_assert(sizeof(void*) == 8, "load addr differs on 64bit");
  const uintptr_t baddr = 0x00400000;
#else
  _Static_assert(sizeof(void*) == 4, "assuming load address for 32bit, but "
                 "system is not 32bit.");
  const uintptr_t baddr = 0x08048000;
#endif
  if(inferior_pid == -1) { return -EINVAL; }
  if(read_inferior(into, offset+baddr, n, inferior_pid) != 0) {
    return -errno;
  }
  return n; /* if everything went well, return the number of bytes read. */
}

/* reads the 'idx' string table from the inferior.
 * EINVAL   idx is invalid
 * ENOENT   idx is not a string table */
MALLOC static char*
read_strtab(rdinf* rd, const Elf64_Ehdr eh, size_t idx) {
  assert(valid_header(&eh));
  assert(sizeof(Elf64_Shdr) == eh.e_shentsize);
  const uintptr_t secstart = eh.e_shoff;
  const size_t nsections = eh.e_shnum;
  const size_t shsz = sizeof(Elf64_Shdr);
  if(idx > nsections) { errno = EINVAL; return NULL; }
  Elf64_Shdr shdr;
  if(rd(&shdr, shsz, secstart + idx*shsz) != (int)shsz) {
    const int err = errno;
    fprintf(stderr, "short read for section header %zu: %d\n", idx, errno);
    errno = err;
    return NULL;
  }
  if(shdr.sh_type != SHT_STRTAB) { errno = ENOENT; return NULL; }
  char* strings = malloc(shdr.sh_size);
  if(rd(strings, shdr.sh_size, shdr.sh_offset) != (int)shdr.sh_size) {
    const int err = errno;
    fprintf(stderr, "error reading string table %zu: %d\n", idx, errno);
    free(strings);
    errno = err;
    return NULL;
  }
  return strings;
}

void
free_symtable(symtable_t* sym) {
  for(size_t i=0; i < sym->n; ++i) {
    free(sym->bols[i].name);
    sym->bols[i].name = 0x0;
    sym->bols[i].address = 0xdeadbeef;
  }
  free(sym->bols);
  free(sym);
}

symtable_t*
read_symtab(rdinf* rd) {
  assert(procfd != -1);

  Elf64_Ehdr ehdr;
  if(rd(&ehdr, sizeof(Elf64_Ehdr), 0) != (int)sizeof(Elf64_Ehdr)) {
    fprintf(stderr, "could not read ELF header.\n");
    return NULL;
  }
  fprintf(stderr, "load time address: 0x%0lx\n", ehdr.e_entry);
  assert(valid_header(&ehdr));

  symtable_t* sym = calloc(1, sizeof(symtable_t));
  sym->n = 0;

  const uintptr_t shstart = ehdr.e_shoff;
  printf("Iterating over %d headers.\n", ehdr.e_shnum);
  const size_t shsz = sizeof(Elf64_Shdr);
  for(size_t i=0; i < ehdr.e_shnum; ++i) {
    Elf64_Shdr shdr;
    if(rd(&shdr, shsz, shstart+i*shsz) != (int)shsz) {
      fprintf(stderr, "error reading shdr %zu: %d\n", i, errno);
      continue;
    }
    if(shdr.sh_type == SHT_STRTAB) {
      printf("String table in section %zu.\n", i);
    }
    if(shdr.sh_type == SHT_SYMTAB) {
      /* -1: we skip the first symbol.  It is always a null symbol, apparently
       * so other things can reference 'symbol index 0' to indicate that the
       * symbol is unknown or broken or whatever. */
      const size_t nsyms = (shdr.sh_size / sizeof(Elf64_Sym)) - 1;
      Elf64_Sym* elfsyms = malloc(shdr.sh_size);
      const size_t bytes = shdr.sh_size;
      if(rd(elfsyms, bytes, shdr.sh_offset) != (int)bytes) {
        fprintf(stderr, "%zu could not read symtab: %d\n", i, errno);
        free(elfsyms);
        continue; /* skip this symbol table. */
      }
      char* strtable = read_strtab(rd, ehdr, shdr.sh_link);
      if(strtable == NULL) {
        perror("reading string table");
        free(elfsyms);
        continue; /* skip this symbol table. */
      }
      sym->bols = realloc(sym->bols, sizeof(symbol)*(sym->n+nsyms));
      for(size_t i=0; i < nsyms; ++i) {
        sym->bols[i+sym->n].name = strdup(&strtable[elfsyms[i+1].st_name]);
        sym->bols[i+sym->n].address = elfsyms[i+1].st_value;
      }
      sym->n += nsyms;
      free(strtable);
      free(elfsyms);
    }
    if(shdr.sh_type == SHT_DYNSYM) {
      /* this should be its own function, it's the same as for SYMTAB. */
      /* -1: we skip the first symbol.  It is always a null symbol, apparently
       * so other things can reference 'symbol index 0' to indicate that the
       * symbol is unknown or broken or whatever. */
      const size_t nsyms = (shdr.sh_size / sizeof(Elf64_Sym)) - 1;
      printf("adding %zu dynsym symbols\n", nsyms);
      Elf64_Sym* elfsyms = malloc(shdr.sh_size);
      const size_t bytes = shdr.sh_size;
      if(rd(elfsyms, bytes, shdr.sh_offset) != (int)bytes) {
        fprintf(stderr, "%zu could not read dynsymtab: %d\n", i, errno);
        free(elfsyms);
        continue; /* skip this symbol table. */
      }
      char* strtable = read_strtab(rd, ehdr, shdr.sh_link);
      if(strtable == NULL) {
        perror("reading dynsym string table");
        free(elfsyms);
        continue; /* skip this symbol table. */
      }
      sym->bols = realloc(sym->bols, sizeof(symbol)*(sym->n+nsyms));
      for(size_t i=0; i < nsyms; ++i) {
        sym->bols[i+sym->n].name = strdup(&strtable[elfsyms[i+1].st_name]);
        sym->bols[i+sym->n].address = elfsyms[i+1].st_value;
      }
      sym->n += nsyms;
      free(strtable);
      free(elfsyms);
    }
  }
  return sym;
}

int
symcompar(const void* a, const void* b) {
  const symbol* sa = (const symbol*)a;
  const symbol* sb = (const symbol*)b;
  return strcmp(sa->name, sb->name);
}

static void
printsyms(const symtable_t* sym) {
  for(size_t i=0; i < sym->n; ++i) {
    printf("\t sym %2zu: %30s 0x%0lx\n", i, sym->bols[i].name,
           sym->bols[i].address);
  }
}
const symbol*
find_symbol(const char* name, const symtable_t* sym) {
  for(size_t i=0; i < sym->n; ++i) {
    const int compar = strcmp(sym->bols[i].name, name);
    if(compar == 0) {
      return &sym->bols[i];
    } else if(compar > 0) { /* the table is sorted. */
      return NULL;
    }
  }
  return NULL;
}

/* Somewhere inside the _DYNAMIC section of the inferior's memory, we should
 * find a DT_DEBUG symbol.  If there's no debug info at all, then eventually
 * we'll just run off the process' address space and get an errno while
 * reading.  The DT_DEBUG leads us to the link_map structure.
 * @param addr_dynamic address of the _DYNAMIC symbol in the inferior. */
uintptr_t
lmap_head(pid_t inferior, uintptr_t addr_dynamic) {
  errno=0;
  for(uintptr_t dynaddr=addr_dynamic; errno==0; dynaddr+=sizeof(Elf64_Dyn)) {
    errno = 0;
    /* this 'tag' is the d_tag of an Elf64_Dyn */
    long tag = ptrace(PTRACE_PEEKDATA, inferior, dynaddr, 0);
    if(errno != 0) {
      assert(tag == -1);
      fprintf(stderr, "could not read tag.\n");
      return 0x0;
    }
    switch(tag) {
      case DT_NULL: errno=ENOENT; break; /* bail out, end of Dyns. */
      case DT_DEBUG: {
        printf("found the debug tag at address 0x%0lx\n", dynaddr);
        /* at tag +1 word, we find the pointer to the r_debug struct. */
        errno=0;
        const long rdbg = ptrace(PTRACE_PEEKDATA, inferior,
                                 dynaddr+sizeof(Elf64_Sxword), 0);
        if(errno != 0) {
          fprintf(stderr, "ptrace r_debug base read err: %d\n", errno);
          return 0x0;
        }
        /* we can read the r_debug now, but we want the link map. */
        const uintptr_t lmapaddr = rdbg + offsetof(struct r_debug, r_map);
        /* now we have the address of r_map, but we want r_map itself. */
        const long lmap = ptrace(PTRACE_PEEKDATA, inferior, lmapaddr, 0);
        if(errno != 0) {
          fprintf(stderr, "ptrace r_map base read err: %d\n", errno);
          return 0x0;
        }
        return (uintptr_t)lmap;
      }
    }
  }
  return 0x0;
}

MALLOC struct link_map*
load_lmap(pid_t inferior, uintptr_t laddr) {
  struct link_map* rv = calloc(1, sizeof(struct link_map));
  errno=0;
  if(read_inferior(&rv->l_addr, laddr, sizeof(Elf64_Addr), inferior)) {
    fprintf(stderr, "error reading library addr: %d\n", errno);
  }
  if(read_inferior(&rv->l_name, laddr+offsetof(struct link_map,l_name),
                   sizeof(char*), inferior)) {
    fprintf(stderr, "error reading addr of library name: %d\n", errno);
  }
  if(read_inferior(&rv->l_ld, laddr+offsetof(struct link_map,l_ld),
                   sizeof(Elf64_Dyn*), inferior)) {
    fprintf(stderr, "error reading l_ld of library: %d\n", errno);
  }
  if(read_inferior(&rv->l_next, laddr+offsetof(struct link_map,l_next),
                   sizeof(struct link_map*), inferior)) {
    fprintf(stderr, "error reading l_next of library: %d\n", errno);
  }
  if(read_inferior(&rv->l_prev, laddr+offsetof(struct link_map,l_prev),
                   sizeof(struct link_map*), inferior)) {
    fprintf(stderr, "error reading l_prev of library: %d\n", errno);
  }
  if(errno != 0) {
    fprintf(stderr, "Error loading link_map fields: %d\n", errno);
    free(rv);
    return NULL;
  }
  /* instead of the address of the name, let's get the actual/real name. */
  const uintptr_t lname = (uintptr_t)rv->l_name;
  /* how big is the string?  we don't know.  let's just read a lot.  it should
   * be null-terminated, so hopefully this is okay.. */
  rv->l_name = calloc(256, sizeof(char));
  if(read_inferior(rv->l_name, lname, 256, inferior) != 0) {
    fprintf(stderr, "error reading library name (lmap) string: %d\n", errno);
  }
  return rv;
}

void
free_lmap(struct link_map* lm) {
  free(lm->l_name);
  free(lm);
}

/* A symbol filter.  If true, the symbol is allowed to stay. */
typedef bool(symfilt)(const symbol s, void*);
/* @return the symbols that pass the function from the list 'sy'.  The symbols
 * are deep-copied, to allow 'sy' to be freed afterwards. */
symtable_t*
filter_symbols(const symtable_t* sy, symfilt* youshallpass, void* user) {
  symtable_t* newsym = calloc(1, sizeof(symtable_t));
  newsym->n = 0;
  newsym->bols = calloc(sy->n, sizeof(symbol));
  for(size_t i=0; i < sy->n; ++i) {
    if(!youshallpass(sy->bols[i],user)) {continue;} /* RIP Gandalf the Grey. */
    /* strdup: we need/want to deepcopy. */
    newsym->bols[newsym->n].name = strdup(sy->bols[i].name);
    newsym->bols[newsym->n].address = sy->bols[i].address;
    newsym->n++;
  }
  return newsym;
}
bool
already_present(const symbol s, void* existing_table) {
  const symtable_t* existing = (const symtable_t*)existing_table;
  return find_symbol(s.name, existing) != NULL;
}

/* offsets the symbols by the given base address... if that makes sense. */
void
relocate_symbols(symtable_t* sym, const uintptr_t offset) {
  for(size_t i=0; i < sym->n; ++i) {
    /* There are some 'special' symbols that must NOT be relocated.  SHN_UNDEF
     * and SHN_ABS ones, for example.  I believe SHN_COMMON symbols should not
     * be relocated either.  However, we did not save the symbol type when we
     * built the table, so we can't do that filtering here.  We're going to let
     * it slide, on the basis that our nefarious purposes do not need to fiddle
     * with such symbols. */
    sym->bols[i].address += offset;
  }
}

static symtable_t*
merge_symtables(const symtable_t* a, const symtable_t* b) {
  symtable_t* merged = malloc(sizeof(symtable_t));
  merged->n = a->n + b->n;
  merged->bols = calloc(merged->n, sizeof(symbol));
  for(size_t i=0; i < a->n; ++i) {
    merged->bols[i].name = strdup(a->bols[i].name);
    merged->bols[i].address = a->bols[i].address;
  }
  for(size_t i=0; i < b->n; ++i) {
    merged->bols[i+a->n].name = strdup(b->bols[i].name);
    merged->bols[i+a->n].address = b->bols[i].address;
  }
  qsort(merged->bols, merged->n, sizeof(symbol), symcompar);
  return merged;
}
/* When an executable calls a function in a library, that library symbol
 * appears in the executable.  Of course, the linker has no idea where that
 * library symbol will be at runtime, so it gives the symbol an address of 0x0
 * and expects the loader to fix things up.
 * Since *we* are the loader, we need to fix things up.  The second symtable,
 * 'with', should come from the library that actually owns the symbol.  We use
 * that symtable to correct the symbols in 'dest'. */
void
fix_symbols(symtable_t* dest, const symtable_t* with) {
  for(size_t i=0; i < dest->n; ++i) {
    if(dest->bols[i].address == 0x0) {
      const symbol* srch = find_symbol(dest->bols[i].name, with);
      if(srch != NULL) {
        assert(srch->address != 0x0);
        dest->bols[i].address = srch->address;
      }
    }
  }
}
