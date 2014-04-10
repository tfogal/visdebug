#ifndef SITUDBG_CFG_H
#define SITUDBG_CFG_H
#ifdef __cplusplus
# include <cstdlib>
# define EXTC extern "C"
#else
# include <stdlib.h>
# define EXTC
#endif

EXTC struct node* cfg(const char* program, size_t* n_nodes);

#endif
