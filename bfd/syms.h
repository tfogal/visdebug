#include <stdbool.h>
#include <stdlib.h>
#include <link.h>
#include "../cfg/compiler.h"

typedef struct _symbol {
  char* name;
  uintptr_t address;
} symbol;
typedef struct _symtable {
  size_t n;
  symbol* bols;
} symtable_t;

typedef long(rdinf)(void* into, size_t n, size_t offset);
symtable_t* read_symtab(rdinf* rd);
symtable_t* read_symtab_procread();
void setprocfd(int x);
void free_symtable(symtable_t* sym);
PURE size_t Elf64_Dynsz();
PURE size_t Elf64_Sxwordsz();
PURE size_t rmap_offset();
PURE uintptr_t uintptr(const void*);
PURE size_t lmap_lname_offset();
PURE size_t lmap_lnext_offset();
