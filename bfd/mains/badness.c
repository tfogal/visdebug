/* read symbols from running process. */
/* 1. find _DYNAMIC in normal symtable
 * 2. _Sym's st_value for _DYNAMIC gives d_tag of an Elf64_Dyn in inferior
 * 3. if _Dyn's tag is DT_DEBUG, than +1 word is the _Dyn's d_ptr, PEEK it
 * 4. offsetof(r_debug, r_map) at the d_ptr gives the first link_map
 * 5. iterate through the link_maps to load them. mostly their l_names.
 * 6. foreach link_map's l_name, read symbols from that library (l_name)
 * 7. resolve each symbol by adding link_map's.l_addr into its st_value */
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include "wrapbfd.h"
#include "../cfg/compiler.h"

static int linux_read_memory(unsigned long from, unsigned char *to, size_t len,
                             const pid_t pid);

/* returns >0 on success. */
static int
read_inferior(void* buf, uintptr_t base, size_t bytes, pid_t inferior) {
#if 0
  assert(inferior > 0); /* PID must be valid. */
  errno = 0;
  uintptr_t* data = (uintptr_t*)buf;
  for(size_t i=0; i < bytes / 8; ++i) {
    data[i*8] = ptrace(PTRACE_PEEKTEXT, inferior, base + (i*8), NULL);
    if(errno) { return errno; }
  }
  /* unless 'bytes' is a multiple of the word size, there's a few bytes left
   * over.  this relies on integer arithmetic and breaks if the compiler thinks
   * it's smarter than us.*/
  const size_t bytes_read = (bytes/8)*8;
  long word = ptrace(PTRACE_PEEKTEXT, inferior, base + bytes_read, NULL);
  if(errno) { return errno; }
  const size_t leftover = bytes - bytes_read;
  memcpy(data+bytes_read, &word, leftover);
  return 0;
#else
  int rv;
  if((rv = linux_read_memory(base, buf, bytes, inferior)) != 0) {
    char errmsg[512];
    if(strerror_r(errno, errmsg, 512) != 0) {
      perror("error getting error. wow.");
      abort();
    }
    fprintf(stderr, "error(%d) reading memory: %s\n", errno, errmsg);
  }
  return rv;
#endif
}

static bool
valid_header(const Elf64_Ehdr* ehdr) {
#if 0
  printf("program header table is +%ld bytes\n", ehdr->e_phoff);
  printf("section header table is +%ld bytes\n", ehdr->e_shoff);
  printf("execution starts at: 0x%0lx\ntype: ", ehdr->e_entry);
  switch(ehdr->e_type) {
    case ET_NONE: printf("no type, impossible\n"); break;
    case ET_REL: puts("relocatable"); break;
    case ET_EXEC: puts("executable"); break;
    case ET_DYN: puts("shared object"); break;
    case ET_CORE: puts("core"); break;
    default: puts("other object type.."); return false;
  }
#endif
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

static uintptr_t
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

static pid_t inferior_pid = 0;
static void
handle_signal(int sig) {
  signal(sig, SIG_DFL);
  psignal(sig, "sig received in parent, detaching and shutting down");
  if(inferior_pid) {
    ptrace(PTRACE_DETACH, inferior_pid, 0,0);
  }
  exit(EXIT_FAILURE);
}

static void build_stab(pid_t inferior);
static void blah(pid_t inferior);
int
main(int argc, char *argv[]) {
  if(argc != 2) {
    fprintf(stderr, "need PID to analyze\n");
    return EXIT_FAILURE;
  }
  (void)argv;

  const pid_t inferior = (pid_t)atoi(argv[1]);
  if(ptrace(PTRACE_ATTACH, inferior, 0,0)) {
    perror("ptrace");
    ptrace(PTRACE_DETACH, inferior, 0,0);
    return EXIT_FAILURE;
  }
  { /* make sure child loses ATTACHd state if we die. */
    inferior_pid = inferior;
    for(size_t i=0; i < _NSIG; ++i) {
      if(SIGCHLD != i) {
        signal(i, handle_signal);
      }
    }
  }

  char exe[128];
  snprintf(exe, 128, "/proc/%ld/exe", (long)inferior);
  const int fd = open(exe, O_RDONLY);
  if(fd == -1) {
    ptrace(PTRACE_DETACH, inferior, 0,0);
    return EXIT_FAILURE;
  }
  close(fd);

#if 0
  build_stab(inferior);
#else
  blah(inferior);
#endif

  if(ptrace(PTRACE_DETACH, inferior, 0,0)) {
    perror("detaching");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

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

  goto no_proc;
  /* Try using /proc first. */
  ssize_t bytes;

  /* We could keep this file open and cache it - possibly one per
     thread.  That requires some juggling, but is even faster.  */
  char filename[64];
  snprintf(filename, 64, "/proc/%d/mem", (int)pid);
  int fd = open(filename, O_RDONLY | O_LARGEFILE);
  if(fd == -1) {
    fprintf(stderr, "no memory map.  falling back on ptrace method\n");
    goto no_proc;
  }

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

  /* Read all the longwords */
  errno = 0;
  size_t i;
  for (i = 0; i < count; i++, addr += sizeof (PTRACE_XFER_TYPE)) {
      buffer[i] = ptrace(PTRACE_PEEKTEXT, pid, (uintptr_t) addr, 0);
      if(errno) {
        fprintf(stderr, "ptrace read mem error at iter %zu\n", i);
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
typedef int(rdinf)(void* into, size_t n, size_t offset);
static int procfd = -1;
static int
procread(void* into, size_t n, size_t offset) {
  if(procfd == -1) { return -EINVAL; }
  return pread(procfd, into, n, offset);
}
/* Reads from the inferior's memory.  The offset is relative: we compensate for
 * the load address of the binary automatically */
static int
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

typedef struct _symbol {
  char* name;
  uintptr_t address;
} symbol;
typedef struct _symtable {
  size_t n;
  symbol* bols;
} symtable_t;

static void
free_symtable(symtable_t* sym) {
  for(size_t i=0; i < sym->n; ++i) {
    free(sym->bols[i].name);
    sym->bols[i].name = 0x0;
    sym->bols[i].address = 0xdeadbeef;
  }
  free(sym->bols);
}

static void
blah(pid_t inferior) {
  char ex[128]; snprintf(ex, 128, "/proc/%ld/exe", (long)inferior);
  procfd = open(ex, O_RDONLY);
  if(procfd == -1) { perror("open"); return; }

  rdinf* rd = procread;

  Elf64_Ehdr ehdr;
  if(rd(&ehdr, sizeof(Elf64_Ehdr), 0) != (int)sizeof(Elf64_Ehdr)) {
    fprintf(stderr, "could not read sec ELF header.\n");
    close(procfd); procfd = -1;
    return;
  }
  assert(valid_header(&ehdr));

  symtable_t sym = {0, NULL};

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
      const size_t nsyms = shdr.sh_size / sizeof(Elf64_Sym);
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
      sym.bols = realloc(sym.bols, sizeof(symbol)*(sym.n+nsyms));
      for(size_t i=0; i < nsyms; ++i) {
        sym.bols[i+sym.n].name = strdup(&strtable[elfsyms[i].st_name]);
        sym.bols[i+sym.n].address = elfsyms[i].st_value;
      }
      sym.n += nsyms;
      free(strtable);
      free(elfsyms);
    }
  }
  printf("Found %zu symbols.\n", sym.n);
  for(size_t i=0; i < sym.n; ++i) {
    printf("\t sym %2zu: %30s 0x%0lx\n", i, sym.bols[i].name,
           sym.bols[i].address);
  }
}

static void
build_stab(pid_t inferior) {
  Elf64_Ehdr ehdr;

#ifdef _LP64
  _Static_assert(sizeof(void*) == 8, "load addr differs on 64bit");
  const uintptr_t baddr = 0x00400000;
#else
  _Static_assert(sizeof(void*) == 4, "assuming load address for 32bit, but "
                 "system is not 32bit.");
  const uintptr_t baddr = 0x08048000;
#endif

  if(read_inferior(&ehdr, baddr, sizeof(Elf64_Ehdr), inferior)) {
    perror("ptrace ehdr");
    return;
  }
  if(!valid_header(&ehdr)) {
    fprintf(stderr, "invalid ELF header.\n");
    return;
  }
  {
    Elf64_Ehdr eh2;
    char ex[128]; snprintf(ex, 128, "/proc/%ld/exe", (long)inferior);
    const int fd = open(ex, O_RDONLY);
    if(fd == -1) { perror("open"); return; }
#if 0
    /* if we open /proc/$pid/mem instead, we need to seek to the base address.
     * then we can (correctly) read the program header.. but not the first
     * section. */
    if(lseek(fd, baddr, SEEK_SET) == -1) {
      perror("lseek");
    }
#endif
    if(read(fd, &eh2, sizeof(Elf64_Ehdr)) < (int)sizeof(Elf64_Ehdr)) {
      perror("shor tread");
    }
    if(memcmp(&ehdr, &eh2, sizeof(Elf64_Ehdr)) != 0) {
      fprintf(stderr, "mem is not equal!\n");
      return;
    } else {
      printf("*** headers match *** :-)\n");
    }
    const uintptr_t shstart = ehdr.e_shoff;
    printf("Iterating over %d headers.\n", ehdr.e_shnum);
    for(size_t i=0; i < ehdr.e_shnum; ++i) {
      Elf64_Shdr shdr;
      const size_t shsz = sizeof(Elf64_Shdr);
      assert(shsz == ehdr.e_shentsize);
      printf("reading header %zu at %zu\n", i, shstart+i*shsz);
      if(pread(fd, &shdr, shsz, shstart+i*shsz) != (int)shsz) {
        fprintf(stderr, "short read on sec header %zu: %d\n", i, errno);
        return;
      }
      switch(shdr.sh_type) {
        case SHT_SYMTAB: {
          printf("found symbtab.  %zu symbols.\n",
                 shdr.sh_size / sizeof(Elf64_Sym));
          const size_t nsyms = shdr.sh_size / sizeof(Elf64_Sym);
          Elf64_Sym* syms = malloc(shdr.sh_size);
          if(pread(fd, syms, shdr.sh_size, shdr.sh_offset) !=
             (int)shdr.sh_size) {
            fprintf(stderr, "%zu could not read symtab: %d\n", i, errno);
            free(syms);
            continue;
          }
          /* that's just the symbols---we want their names, too.  sh_link
           * gives the index into the array of tables that houses the
           * associated string table. */
          const size_t stroff = ehdr.e_shoff + shdr.sh_link*shsz;
          printf("we think strtab is at %zu (link: %d)\n", stroff,
                 shdr.sh_link);
          if(pread(fd, &shdr, shsz, stroff) != (int)shsz) {
            fprintf(stderr, "error reading string table header: %d\n", errno);
            free(syms);
            continue;
          }
          char* strings = malloc(shdr.sh_size);
          if(pread(fd, strings, shdr.sh_size, shdr.sh_offset) != (int)shdr.sh_size) {
            fprintf(stderr, "error reading string table: %d\n", errno);
            free(syms); free(strings);
            continue;
          }
          for(size_t i=0; i < nsyms; ++i) {
#if 1
            printf("\tsym %zu: %s 0x%0lx\n", i, &strings[syms[i].st_name],
                   syms[i].st_value);
#endif
          }
          free(syms); free(strings);
          break;
        }
        case SHT_STRTAB: {
          printf("string table\n");
          char* strings = malloc(shdr.sh_size);
          if(pread(fd, strings, shdr.sh_size, shdr.sh_offset) != (int)shdr.sh_size) {
            fprintf(stderr, "error reading string table: %d\n", errno);
            free(strings);
            continue;
          }
          free(strings);
          break;
        }
        case SHT_DYNAMIC: {
          const size_t ndytbl = shdr.sh_size / sizeof(Elf64_Dyn);
          printf("found dynamic section with %zu dyns, linked section %d\n",
                 ndytbl, shdr.sh_link);
          Elf64_Dyn* dyns = malloc(shdr.sh_size);
          if(pread(fd, dyns, shdr.sh_size, shdr.sh_offset) !=
             (int)shdr.sh_size) {
            fprintf(stderr, "%zu could not read dytable: %d\n", i, errno);
            continue;
          }
          uintptr_t raaddr;
          size_t rabytes;
          size_t rabytes_entry;
          for(size_t i=0; i < ndytbl; ++i) {
            switch(dyns[i].d_tag) {
              case DT_RELA:
                printf("\t%2zu: Rela table is at 0x%0lx\n", i,
                       dyns[i].d_un.d_ptr);
                raaddr = dyns[i].d_un.d_ptr;
                break;
              case DT_RELASZ:
                printf("\t%2zu: Rela table is %ld bytes\n", i,
                       dyns[i].d_un.d_val);
                rabytes = dyns[i].d_un.d_val;
                break;
              case DT_RELAENT:
                printf("\t%2zu: each rela entry is %ld bytes\n", i,
                       dyns[i].d_un.d_val);
                rabytes_entry = dyns[i].d_un.d_val;
                break;
              case DT_PLTREL:
                assert(dyns[i].d_un.d_val == DT_RELA &&
                       "dyn code assumes RELAs.");
            }
          }
          free(dyns);
          const size_t nrelas = rabytes / rabytes_entry;
          Elf64_Rela* relas = malloc(rabytes);
          const size_t reladdr = baddr + raaddr;
          printf("reading relocAs from 0x%0lx\n", reladdr);
          if(pread(fd, relas, rabytes, reladdr) != (int)rabytes) {
            fprintf(stderr, "could not read relocA entries: %d\n", errno);
            continue;
          }
          for(size_t i=0; i < nrelas; ++i) {
          }
          free(relas);
          break;
        }
      }
    }
    close(fd);
  }
}
