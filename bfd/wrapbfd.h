#ifndef GO_WRAPBFD_H
#define GO_WRAPBFD_H

#include <inttypes.h>
#include "bfd.h"

size_t symtabsz(bfd* b);
size_t nsyms(bfd* b, int dynamic, asymbol** syms, unsigned* sz);
asymbol** readsyms(bfd* b, unsigned* sz);
uintptr_t addr(const asymbol* sym);

#endif
