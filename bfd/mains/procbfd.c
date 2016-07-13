/* Distributed under the MIT license.  See the LICENSE file.
 * Copyright (c) 2014--2016 Thomas Fogal */
/* small test program to use BFD on memory from a process. */
#define _POSIX_C_SOURCE 201212L
#define _LARGEFILE64_SOURCE 1
#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
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
#include <elf.h>
#include <link.h>
#include "../wrapbfd.h"
#include "../../cfg/compiler.h"

static struct link_map* locate_linkmap(pid_t pid);
static int linux_read_memory(unsigned long from, unsigned char *to, size_t len,
                             const pid_t pid);
static void cat_maps(pid_t pid);
static void build_stab(pid_t inferior);


static void
read_process_elf(pid_t chld) {
#if 0
  struct link_map* lmap = locate_linkmap(chld);
  free(lmap);
#else
  build_stab(chld);
#endif
}

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

/* hacky way to get the loader to run. */
static void
skip_until_main(pid_t chld) {
  printf("currently at 0x%0lx. skipping a bunch.\n", whereami(chld));
  size_t insns = 0;
  do {
    if(ptrace(PTRACE_SINGLESTEP, chld, 0,0) != 0) {
      perror("singlestep");
      return;
    }
    if(waitpid(chld, NULL, 0) != chld) {
      perror("waitpid skipping");
      return;
    }
  } while(insns++ <= 25000);
  printf("finished skipping.  now at 0x%0lx.\n", whereami(chld));
}

static void
break_for_start(uintptr_t entry, pid_t pid) {
  errno = 0;
  printf("currently at 0x%0lx.  setting breakpoint.\n", whereami(pid));
  long word = ptrace(PTRACE_PEEKTEXT, pid, entry, 0);
  if(errno) {
    perror("reading entry point");
    return;
  }
  /* replace high bytes with 0xcc, the breakpoint insn */
  /*long breakword = (0xccULL << 56) | (0x00FFFFFFFFFFFFFF & word);*/
  long breakword = (0xFFFFFFFFFFFFFFFF & word) | 0xcc;
  if(ptrace(PTRACE_POKETEXT, pid, entry, breakword)) {
    perror("writing entry point");
    return;
  }
  printf("inserted breakpoint.  continuing until we hit it...\n");
  errno = 0;
  if(ptrace(PTRACE_CONT, pid, 0,0)) {
    perror("continuing proc");
    return;
  }
  printf("hit breakpoint, we're now at 0x%0lx\n", whereami(pid));
  if(ptrace(PTRACE_POKETEXT, pid, entry, word)) {
    perror("restoring entry point");
    return;
  }
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

static struct link_map *
locate_linkmap(pid_t pid) {
  Elf64_Ehdr *ehdr = malloc(sizeof(Elf64_Ehdr));

  /* 
   * first we check the elf header, mapped at 0x08048000, the offset
   * to the program header table from where we try to locate
   * PT_DYNAMIC section.
   */
#ifdef _LP64
  _Static_assert(sizeof(void*) == 8, "load addr differs on 64bit");
  const uintptr_t baddr = 0x00400000;
#else
  _Static_assert(sizeof(void*) == 4, "assuming load address for 32bit, but "
                 "system is not 32bit.");
  const uintptr_t baddr = 0x08048000;
#endif
  if(read_inferior(ehdr, baddr, sizeof(Elf64_Ehdr), pid) != 0) {
    perror("ptrace ehdr");
    free(ehdr);
    return NULL;
  }
  if(!valid_header(ehdr)) {
    fprintf(stderr, "invalid elf header?\n");
    free(ehdr);
    return NULL;
  }
  //break_for_start(ehdr->e_entry, pid);
  //print_section_headers(baddr + ehdr->e_shoff, ehdr->e_shnum, pid);
  if(ehdr->e_phoff == 0) {
    fprintf(stderr, "there is no program header table!!\n");
    free(ehdr);
    return NULL;
  }
  Elf64_Phdr *phdr = malloc(sizeof(Elf64_Phdr));
  const uintptr_t phdr_addr = baddr + ehdr->e_phoff;
  printf("program header at %p\n",(void *) phdr_addr);
  free(ehdr); ehdr = NULL;
  if(read_inferior(phdr, phdr_addr, sizeof(Elf64_Phdr), pid)) {
    perror("ptrace phdr");
    free(phdr);
    return NULL;
  }
  if(!valid_pheader(phdr)) {
    fprintf(stderr, "nonsensical program header\n");
    free(phdr);
    return NULL;
  }

  for(size_t i=0; phdr->p_type != PT_DYNAMIC && i < 1024; ++i) {
    if(read_inferior(phdr, phdr_addr + i*sizeof(Elf64_Phdr),
                     sizeof(Elf64_Phdr), pid)) {
      perror("ptrace search");
      free(phdr);
      return NULL;
    }
    printf("searching... %zu\n", i);
  }
  assert(phdr->p_type == PT_DYNAMIC);
  printf("found DYNAMIC section at 0x%lx\n", phdr_addr);
  printf("vaddr: 0x%lx\n", phdr->p_vaddr);
  
  /* look for the address of the GOT in the dynamic section we just found. */
  const uintptr_t dyn_addr = phdr->p_vaddr;
  free(phdr); phdr = NULL;
  Elf64_Dyn *dyn = find_got(pid, dyn_addr);
  section_names(pid, dyn_addr);

  /* + 8 because we want the second entry. */
  const Elf64_Addr pltaddr = dyn->d_un.d_ptr + 8;
  free(dyn); dyn = NULL;
  /* 
   * now just read first link_map item and return it 
   */
  uintptr_t map_addr;
  if(read_inferior(&map_addr, pltaddr, 8, pid)) {
    perror("could not get map addr");
    return NULL;
  }
  printf("link map's address: 0x%0lx\n", map_addr);
  struct link_map *l = malloc(sizeof(struct link_map));
  if(read_inferior(l, baddr+map_addr, sizeof(struct link_map), pid)) {
    perror("reading linkmap");
  }
  return l;
}

__attribute__((unused)) static void
cat_maps(pid_t pid) {
  char filename[128];
  snprintf(filename, 128, "/proc/%d/maps", (int)pid);
  const int fd = open(filename, O_RDONLY | O_LARGEFILE);
  if(fd == -1) {
    fprintf(stderr, "could not read map!\n");
    return;
  }
  char* buf = malloc(1024);
  ssize_t bytes = 1;
  do {
    bytes = read(fd, buf, 1024);
    if(bytes < 0) {
      perror("read maps");
      free(buf);
      close(fd);
      return;
    }
    write(STDOUT_FILENO, buf, bytes);
  } while(bytes > 0);
  free(buf);
  close(fd);
}

__attribute__((unused)) static void
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

static void
run_target(char* const argv[]) {
    /* Allow tracing of this process */
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        perror("traceme");
        return;
    }

    printf("target starting. will run '%s'\n", argv[0]);
    execve(argv[0], argv, NULL);
}

int
main(int argc, char *argv[]) {
  if(argc < 2) {
    fprintf(stderr, "need program to analyze\n");
    return EXIT_FAILURE;
  }
  (void)argv;

  /* load/exec our child, but keep it frozen.  this is just so we can look
   * things up using the process. */
  char* const subv[] = {strdup(argv[1]), strdup(argv[2])};
  pid_t child = fork();
  if(child < 0) {
    perror("fork");
    return EXIT_FAILURE;
  } else if(child == 0) {
    run_target(subv);
    fprintf(stderr, "baby killer?\n");
    return EXIT_FAILURE; /* if exec failed, die. */
  }
  /* only the parent reaches here. */
  printf("Child is running as process %d\n", child);
  free(subv[0]);
  free(subv[1]);

  int wstat;
  const pid_t sub = waitpid(child, &wstat, 0);
  assert(sub != 0);
  if(sub < 0) {
    perror("waitpid");
    return EXIT_FAILURE;
  }
  if(!WIFSTOPPED(wstat)) {
    fprintf(stderr, "child is not stopped?\n");
    return EXIT_FAILURE;
  }
  if(ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD |
            PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
            PTRACE_O_TRACEEXEC | PTRACE_O_TRACEVFORKDONE) != 0) {
    perror("setting ptrace options");
    kill(child, SIGKILL);
    return EXIT_FAILURE;
  }
  /* make our child run for a bit.
   * makes sure it gets through loading,
   * so the addresses we read are valid. */
  skip_until_main(child);
  /* now we can read addresses. */
  read_process_elf(child);
  printf("okay, we're done.  detach the child now.\n"); fflush(stdout);
#if 0
  if(ptrace(PTRACE_DETACH, child, 0,0)) {
    perror("detaching");
    return EXIT_FAILURE;
  }
#endif
#if 1
  if(ptrace(PTRACE_CONT, child, 0, 0)) {
    perror("resuming child");
    return EXIT_FAILURE;
  }
  if(waitpid(child, &wstat, 0) < 0) {
    perror("waiting for child to die");
    return EXIT_FAILURE;
  }
#endif

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

  printf("shoff: %ld\n", ehdr.e_shoff);
  for(size_t i=0; i < ehdr.e_shnum; ++i) {
    Elf64_Shdr shdr;
    const size_t shsz = ehdr.e_shentsize;
    assert(shsz == sizeof(Elf64_Shdr));
    if(read_inferior(&shdr, baddr+ehdr.e_shoff, shsz, inferior)) {
      perror("could not get section header");
      return;
    }
  }
}
