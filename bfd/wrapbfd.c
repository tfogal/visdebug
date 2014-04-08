#include <inttypes.h>
#include <stdlib.h>
#include "bfd.h"

size_t symtabsz(bfd* b)
{
  return bfd_get_symtab_upper_bound(b);
}

size_t nsyms(bfd* b, int dynamic, asymbol** syms, unsigned* sz)
{
  return bfd_read_minisymbols(b, dynamic, (void**)syms, sz);
}

asymbol**
readsyms(bfd* b, unsigned* sz)
{
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
