/* This program was modified from the one in the 'mprotect' manual page.
 * It basically just allocates a chunk of memory and then runs through it.  It
 * should really have no side effects when run normally.  But, if we're running
 * it under our replace-mallocs code, it should posix_memalign the memory,
 * mprotect it to be read-only, and then cause a segfault when it gets written
 * to. */
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>

#define handle_error(msg) \
  do { perror(msg); exit(EXIT_FAILURE); } while (0)

static char *buffer;

static void
handler(int sig, siginfo_t *si, void *unused)
{
  (void)unused;
  assert(sig == SIGSEGV);
  printf("[ c] Got SIGSEGV at address: 0x%lx\n", (long) si->si_addr);
  exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
    char *p;
    int pagesize;
    struct sigaction sa;

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        handle_error("sigaction");

    pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1)
        handle_error("sysconf");

    /* Allocate a buffer, which should get replaced by a memalign. */
    buffer = malloc(4*pagesize);
    if (buffer == NULL)
        handle_error("memalign");

    printf("Region: 0x%lx--0x%lx\n", (long)buffer, (long)buffer+4*pagesize);

    for(p = buffer ; (long)p < (long)buffer+4*pagesize; )
        *(p++) = argc > 1 ? argv[1][0] : 'a';

    printf("Loop completed\n");
    exit(EXIT_SUCCESS);
}
