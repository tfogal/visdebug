/* Debugging channels.  Example usage:
 *
 *   DECLARE_CHANNEL(stuff);
 *   TRACE(stuff, "is happening!");
 *   ERR(stuff, "error code is nonzero: %d", errcode);
 *   WARN(stuff, "i think something's wrong?");
 *
 * The user could enable / disable the above channel by setting the
 * DEBUG environment variable:
 *
 *   export DEBUG="stuff=+err,-warn,+trace" */
#ifndef GENERIC_DEBUG_H
#define GENERIC_DEBUG_H 1

#include <stdbool.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

enum DbgChanClass {
  DbgErr=0,
  DbgWarn,
  DbgTrace,
  DbgFixme,
};

struct tuvokdbgchannel {
  unsigned flags;
  char name[32];
};

#define DEFAULT_CHFLAGS \
  (1U << DbgErr) | (1U << DbgWarn) | (1U << DbgFixme)
/* creates a new debug channel.  debug channels are private to implementation,
 * and should not be declared in header files. */
#define DECLARE_CHANNEL(ch) \
  static struct tuvokdbgchannel symb_chn_##ch = { DEFAULT_CHFLAGS, #ch }; \
  __attribute__((constructor(200))) static void \
  ch_init_##ch() { \
    const char* dbg_ = getenv("DEBUG"); \
    symb_parse_options(&symb_chn_##ch, dbg_); \
  }

#define TRACE(ch, args...) \
  symb_dbg(DbgTrace, &symb_chn_##ch, __FUNCTION__, args)
#define ERR(ch, args...) \
  symb_dbg(DbgErr, &symb_chn_##ch, __FUNCTION__, args)
#define WARN(ch, args...) \
  symb_dbg(DbgWarn, &symb_chn_##ch, __FUNCTION__, args)
#define FIXME(ch, args...) \
  symb_dbg(DbgFixme, &symb_chn_##ch, __FUNCTION__, args)

/* for internal use only. */
extern void symb_dbg(enum DbgChanClass, const struct tuvokdbgchannel*,
                     const char* func, const char* format, ...)
                     __attribute__((format(printf, 4, 5)));
extern void symb_parse_options(struct tuvokdbgchannel*, const char* opt);

#ifdef __cplusplus
}
#endif

#endif /* GENERIC_DEBUG_H */
