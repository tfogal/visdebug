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
uintptr_t lmap_head(pid_t inferior, uintptr_t addr);
void setprocfd(int x);
long procread(void* into, size_t n, size_t offset);
int symcompar(const void* a, const void* b);
const symbol* find_symbol(const char* name, const symtable_t* sym);
MALLOC struct link_map* load_lmap(pid_t inferior, uintptr_t laddr);
uintptr_t whereami(pid_t inferior);
int read_inferior(void* buf, uintptr_t base, size_t bytes, pid_t inferior);
void fix_symbols(symtable_t* dest, const symtable_t* with);
void relocate_symbols(symtable_t* sym, const uintptr_t offset);
void free_symtable(symtable_t* sym);
bool already_present(const symbol s, void* existing_table);
typedef bool(symfilt)(const symbol s, void*);
symtable_t* filter_symbols(const symtable_t* sy, symfilt*, void* user);
void free_lmap(struct link_map* lm);
void setinferiorpid(pid_t p);
PURE size_t Elf64_Dynsz();
PURE size_t Elf64_Sxwordsz();
PURE size_t rmap_offset();
PURE uintptr_t uintptr(const void*);
