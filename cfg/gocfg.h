#ifndef SITUDBG_CFG_H
#define SITUDBG_CFG_H
#ifdef __cplusplus
# include <cinttypes>
# include <cstdlib>
# define EXTC extern "C"
#else
# include <inttypes.h>
# include <stdlib.h>
# define EXTC
#endif

struct edge {
  uintptr_t from;
  uintptr_t to;
  unsigned flags;
};

struct node {
  uintptr_t addr;
  const char* name;   /* may be null. */
  struct edge* edgelist; /* dynamically allocated. */
  size_t edges;
};

EXTC struct node* cfg(const char* program, size_t* n_nodes);
EXTC struct node* cfgLocal(const char* program, const char* function,
                           size_t* n_nodes);

#endif
