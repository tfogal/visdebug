#ifndef TJF_COMPILER_H
#define TJF_COMPILER_H

/* MALLOC technically only tells the compiler that the returned value is
 * newly-allocated memory.  However we use it to additionally mean that the
 * *caller* is thereafter responsible for the memory. */

#ifdef __GNUC__
#	define GCONST __attribute__((const))
#	define MALLOC __attribute__((malloc))
#	define PURE __attribute__((pure))
#else
#	define GCONST /* no const function support */
#	define MALLOC /* no malloc function support */
#	define PURE /* no pure function support */
#endif

#endif
