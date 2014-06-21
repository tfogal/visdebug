#ifndef TJF_BADSYNC_H
#define TJF_BADSYNC_H

/* This is embarassing.
 * We need to read the inferior's link_map structures to be able to find
 * symbols.  The correct way to do this is to find the r_brk address in the
 * r_debug structure, insert a break point there, wait for the BP to hit, and
 * check to see if it's RT_CONSISTENT.  That means a library load is done, so
 * we can follow the map one iteration.
 * We don't even have breakpoints working yet.  Also, jesus friggin' christ
 * that's annoying.  So, instead, we just synchronize the debugger/debuggee
 * using a file that they both write known values into, and wait for the other
 * one to do their write.
 * Someday we'll just fix the synchronization to be correct and then we don't
 * need this crap. */
extern void badsync();

#endif
