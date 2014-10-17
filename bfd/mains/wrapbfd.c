#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include "bfd.h"

size_t symtabsz(bfd* b) {
  return bfd_get_symtab_upper_bound(b);
}

size_t
nsyms(bfd* b, int dynamic, asymbol** syms, unsigned* sz) {
  return bfd_read_minisymbols(b, dynamic, (void**)syms, sz);
}

asymbol**
readsyms(bfd* b, unsigned* sz) {
  *sz = 0;
  if ((bfd_get_file_flags(b) & HAS_SYMS) == 0) {
    return NULL;
  }
  const size_t nbytes = bfd_get_symtab_upper_bound(b);
  asymbol** symtab = malloc(nbytes);
  if(symtab == NULL) {
    return NULL;
  }

  const long nsyms = bfd_canonicalize_symtab(b, symtab);
  if(nsyms < 0) {
    free(symtab);
    return NULL;
  }
  *sz = (size_t)nsyms;
  return symtab;
}

uintptr_t addr(const asymbol* sym) { return (uintptr_t)sym->udata.p; }

static pid_t inferior_pid = -1;

static int
rd_inferior(bfd_vma vma, bfd_byte* into, bfd_size_type bytes) {
  /* we assume a word is 64bits... */
  assert(bytes % 8 == 0);
  /* caller should set the PID before calling us. */
  assert(inferior_pid != -1);
  errno = 0;
  for(size_t i=0; i < bytes / 8; ++i) {
    into[i*8] = ptrace(PTRACE_PEEKTEXT, inferior_pid, vma + (i*8), NULL);
    if(errno) { return errno; }
  }
  return 0;
}

bfd*
bfd_from_inferior(bfd* template, uintptr_t vma, pid_t pid) {
  inferior_pid = pid;
  errno = 0;
  bfd* rv = bfd_elf_bfd_from_remote_memory(template, vma, NULL, rd_inferior);
  if(!rv) {
    perror("creating bfd from mem");
  }
  return rv;
}
