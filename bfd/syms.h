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
PURE size_t Elf64_Dynsz();
PURE size_t Elf64_Sxwordsz();
PURE size_t lmap_lname_offset();
PURE size_t lmap_lnext_offset();
void free_symtable(symtable_t* sym);
symtable_t* read_symtab_procread();
PURE size_t rmap_offset();
void setprocfd(int x);
PURE uintptr_t uintptr(const void*);
