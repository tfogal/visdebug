/* Distributed under the MIT license.  See the LICENSE file.
 * Copyright (c) 2014--2016 Thomas Fogal */
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
#include "debug.h"
#include "syms.h"
#include "../cfg/compiler.h"

DECLARE_CHANNEL(headers);
DECLARE_CHANNEL(sections);
DECLARE_CHANNEL(symmeta);

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

typedef long(rdinf)(void* into, size_t n, size_t offset);
static symtable_t* read_symtab(rdinf* rd);

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
  errno=0;
#if 0
  printf("procread %p [%zu:%zu] from %d\n", into, offset, offset+n, procfd);
#endif
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

static symtable_t*
read_symtab(rdinf* rd) {
  if(rd == procread) { assert(procfd != -1); }

  Elf64_Ehdr ehdr;
  if(rd(&ehdr, sizeof(Elf64_Ehdr), 0) != (int)sizeof(Elf64_Ehdr)) {
    fprintf(stderr, "could not read ELF header from %d: %d\n", procfd, errno);
    return NULL;
  }
  TRACE(headers, "load time address: 0x%0lx\n", ehdr.e_entry);
  assert(valid_header(&ehdr));

  symtable_t* sym = calloc(1, sizeof(symtable_t));
  sym->n = 0;

  const uintptr_t shstart = ehdr.e_shoff;
  TRACE(sections, "Iterating over %d headers.\n", ehdr.e_shnum);
  const size_t shsz = sizeof(Elf64_Shdr);
  for(size_t i=0; i < ehdr.e_shnum; ++i) {
    Elf64_Shdr shdr;
    if(rd(&shdr, shsz, shstart+i*shsz) != (int)shsz) {
      fprintf(stderr, "error reading shdr %zu: %d\n", i, errno);
      continue;
    }
    if(shdr.sh_type == SHT_STRTAB) {
      TRACE(sections, "String table in section %zu.\n", i);
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
      TRACE(symmeta, "adding %zu dynsym symbols\n", nsyms);
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
  assert(sym);
  return sym;
}
/* purely because Cgo is a PITA. */
symtable_t* read_symtab_procread() { return read_symtab(procread); }

int
symcompar(const void* a, const void* b) {
  const symbol* sa = (const symbol*)a;
  const symbol* sb = (const symbol*)b;
  return strcmp(sa->name, sb->name);
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

/* these are needed to make up for Go not having any way to grab these sizes. */
PURE size_t Elf64_Dynsz() { return sizeof(Elf64_Dyn); }
PURE size_t Elf64_Sxwordsz() { return sizeof(Elf64_Sxword); }
PURE size_t rmap_offset() { return offsetof(struct r_debug, r_map); }
PURE uintptr_t uintptr(const void* p) { return (uintptr_t)p; }

PURE size_t lmap_lname_offset() { return offsetof(struct link_map, l_name); }
PURE size_t lmap_lnext_offset() { return offsetof(struct link_map, l_next); }

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
