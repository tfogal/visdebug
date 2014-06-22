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
#include "../syms.h"
#include "../wrapbfd.h"
#include "../../cfg/compiler.h"

static pid_t inferior_pid = 0;
static void
handle_signal(int sig) {
  signal(sig, SIG_DFL);
  if(inferior_pid) {
    ptrace(PTRACE_DETACH, inferior_pid, 0,0);
  }
  psignal(sig, "sig received in parent, detaching and shutting down");
  exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[]) {
  if(argc != 2) {
    fprintf(stderr, "need PID to analyze\n");
    return EXIT_FAILURE;
  }
  (void)argv;

  const pid_t inferior = (pid_t)atoi(argv[1]);
  if(ptrace(PTRACE_ATTACH, inferior, 0,0)) {
    perror("ptrace attach");
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
  setprocfd(fd);
  symtable_t* procsym = read_symtab(procread);
  close(fd);
  qsort(procsym->bols, procsym->n, sizeof(symbol), symcompar);
  printf("Read %zu symbols.\n", procsym->n);
  const symbol* dynamic = find_symbol("_DYNAMIC", procsym);
  if(dynamic == NULL) {
    ptrace(PTRACE_DETACH, inferior, 0,0);
    return EXIT_FAILURE;
  }
  
  const uintptr_t head_lmaddr = lmap_head(inferior, dynamic->address);
  printf("lmap hd: 0x%0lx\n", head_lmaddr);

  /* now iterate through each link map and load that thing's symbols. */
  struct link_map* lmap;
  uintptr_t lmaddr = head_lmaddr;
  size_t i=0;
  do {
    lmap = load_lmap(inferior, lmaddr);
    if(i==0) {
      assert(lmap->l_addr == 0x0 && "first lmap should not need relocations!");
    }
    printf("Library %zu loaded at 0x%012lx, next at %14p. [%17s]\n", i++,
           lmap->l_addr, lmap->l_next, lmap->l_name);
    lmaddr = (uintptr_t)lmap->l_next;
    int fd = open(lmap->l_name, O_RDONLY);
    if(lmap->l_name == 0x0 || lmap->l_name[0] == '\0' || fd == -1) {
      free_lmap(lmap);
      continue;
    }
    setprocfd(fd);
    symtable_t* sy = read_symtab(procread);
    close(fd);
    printf("Read %zu symbols from '%s' library.\n", sy->n, lmap->l_name);
    /* But we don't care about most of the symbols.  Drop any of them that the
     * main executable doesn't use. */
    symtable_t* libsym = filter_symbols(sy, already_present, procsym);
    free_symtable(sy);
    /* ld-linux-x86-64* has the symbols we need (i.e. libc functions).
     * libc.so.6 also has these, of course, but I cannot make sense of the
     * addresses in that file.
     * So, for now, this suffices. */
    if(true || strstr(lmap->l_name, "ld-linux-x86-64")) {
      printf("Relocating %zu symbols by 0x%0lx\n", libsym->n, lmap->l_addr);
      relocate_symbols(libsym, lmap->l_addr);
      qsort(libsym->bols, libsym->n, sizeof(symbol), symcompar);
      fix_symbols(procsym, libsym);
    }
    free_symtable(libsym);
    free_lmap(lmap);
  } while(lmaddr);

  /* printsyms(procsym); */

  { const symbol* sympause = find_symbol("pause", procsym);
    if(sympause != NULL) {
      printf("%10s@0x%0lx\n", "pause", sympause->address);
    }
  }
    const symbol* symmalloc = find_symbol("malloc", procsym);
    if(symmalloc == NULL) {
      fprintf(stderr, "no malloc.  giving up.\n");
      ptrace(PTRACE_DETACH, inferior, 0,0);
      return EXIT_FAILURE;
    }
    printf("%10s@0x%012lx\n", "malloc", symmalloc->address);
  { const symbol* symfree= find_symbol("free", procsym);
    printf("%10s@0x%012lx\n", "free", symfree->address);
  }
  { const symbol* symcalloc = find_symbol("calloc", procsym);
    printf("%10s@0x%012lx\n", "calloc", symcalloc->address);
  }
#if 1
  long word;
  if(read_inferior(&word, symmalloc->address, sizeof(long), inferior)) {
    fprintf(stderr, "something went wrong reading malloc: %d\n", errno);
    errno=0;
    word = ptrace(PTRACE_PEEKDATA, inferior, symmalloc->address, 0);
    if(word == -1 && errno != 0) {
      fprintf(stderr, "could not read malloc, AGAIN: %d\n", errno);
    }
  }
  long brkword = (0xccULL << 56) | (0x00FFFFFFFFFFFFFF & word);
  if(ptrace(PTRACE_POKEDATA, inferior, symmalloc->address, brkword) == -1) {
    fprintf(stderr, "inserting breakpoint failed: %d\n", errno);
  }
  {
    printf("set breakpoint.  now telling the tracee to continue.\n");
    if(kill(inferior, SIGCONT) != 0) {
      perror("kill");
    }
  }
  {
  printf("before wait, inferior is at: 0x%0lx\n", whereami(inferior));
  int wstat;
  const pid_t sub = waitpid(inferior, &wstat, 0);
  if(sub < 0) {
    perror("waitpid");
  }
  }
  printf("replacing correct malloc invocation.\n");
  if(ptrace(PTRACE_POKEDATA, inferior, symmalloc->address, word) == -1) {
    fprintf(stderr, "inserting breakpoint failed: %d\n", errno);
  }

  printf("before cont, inferior is at: 0x%0lx\n", whereami(inferior));
  if(ptrace(PTRACE_CONT, inferior, 0,0)) {
    fprintf(stderr, "error continuing! %d\n", errno);
  }
  printf("after  cont, inferior is at: 0x%0lx\n", whereami(inferior));
#endif

  free_symtable(procsym);

  if(ptrace(PTRACE_DETACH, inferior, 0,0)) {
    perror("detaching");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
