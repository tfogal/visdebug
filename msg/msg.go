// A simple package to give channel-based logging to std(err|out).
// A "channel" in this case isn't a go channel, but rather a named conduit for
// logging.  Channels can be enabled or disabled individually.  It is expected
// that users create package-level internal variables and leave them in there.
// Disabling or enabling a channel is then done at run time, with environment
// variables or arguments.
package msg

import "fmt"
import "os"

type Channel interface {
  Error(format string, a ... interface{})
  Warning(format string, a ... interface{})
  Trace(format string, a ... interface{})
}

type stdoutchn struct {
  on uint
}
const (
  bit_ERROR = 1
  bit_WARNING = iota
  bit_TRACE
)
const (
  cnorm = "\033[00m"
  cred = "\033[01;31m";
  cyellow = "\033[01;33m";
  clblue = "\033[01;36m";
)

func (c stdoutchn) Error(format string, a ... interface{}) {
  if (c.on & bit_ERROR) != 0 {
    fmt.Fprintf(os.Stderr, "%s[s] ", cred)
    fmt.Fprintf(os.Stderr, format, a...)
    if format[len(format)-1] != '\n' {
      fmt.Printf("\n")
    }
    fmt.Fprintf(os.Stderr, "%s", cnorm)
  }
}

func (c stdoutchn) Warning(format string, a ... interface{}) {
  if (c.on & bit_WARNING) > 0 {
    fmt.Fprintf(os.Stderr, "%s[s] ", cyellow)
    fmt.Fprintf(os.Stderr, format, a...)
    if format[len(format)-1] != '\n' {
      fmt.Printf("\n")
    }
    fmt.Fprintf(os.Stderr, "%s", cnorm)
  }
}
func (c stdoutchn) Trace(format string, a ... interface{}) {
  if (c.on & bit_TRACE) > 0 {
    fmt.Printf("[s] ")
    fmt.Printf(format, a...)
    if format[len(format)-1] != '\n' {
      fmt.Printf("\n")
    }
  }
}

func (c *stdoutchn) TestEnable() {
  dbg := os.Getenv("DEBUG")
  c.on = bit_ERROR | bit_WARNING
  if dbg != "" && dbg == "+all" { // easy check: all channels on?
    c.on = 0xffffffffffffffff
    return
  }
  for _, c := range dbg {
    fmt.Printf("char: %c\n", c)
  }
}

func StdChan() Channel {
  var rv stdoutchn
  rv.TestEnable()
  return rv
}
