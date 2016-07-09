// A simple package to give channel-based logging to std(err|out).
// A "channel" in this case isn't a go channel, but rather a named conduit for
// logging.  Channels can be enabled or disabled individually.  It is expected
// that users create package-level internal variables and leave them in there.
// Disabling or enabling a channel is then done at run time, using the 'DEBUG'
// environment variable.
package msg

import (
	"fmt"
	"os"
	"strings"
)

type Channel interface {
	Error(format string, a ...interface{})
	Warn(format string, a ...interface{})
	Trace(format string, a ...interface{})
	Printf(format string, a ...interface{})
}

type stdoutchn struct {
	on uint32
}

const (
	bit_ERROR   = uint32(1)
	bit_WARNING = uint32(2)
	bit_TRACE   = uint32(4)
)
const (
	cnorm   = "\033[00m"
	cred    = "\033[01;31m"
	cyellow = "\033[01;33m"
	clblue  = "\033[01;36m"
	cwhgray = "\033[02;40m"
)

// Error prints out an error message to stderr, if error messages are enabled.
func (c stdoutchn) Error(format string, a ...interface{}) {
	if (c.on & bit_ERROR) != 0 {
		fmt.Fprintf(os.Stderr, "%s", cred)
		fmt.Fprintf(os.Stderr, format, a...)
		if format[len(format)-1] != '\n' {
			fmt.Printf("\n")
		}
		fmt.Fprintf(os.Stderr, "%s", cnorm)
	}
}

// Warn prints a warning message to stderr, if warnings are enabled.
func (c stdoutchn) Warn(format string, a ...interface{}) {
	if (c.on & bit_WARNING) > 0 {
		fmt.Fprintf(os.Stderr, "%s", cyellow)
		fmt.Fprintf(os.Stderr, format, a...)
		if format[len(format)-1] != '\n' {
			fmt.Printf("\n")
		}
		fmt.Fprintf(os.Stderr, "%s", cnorm)
	}
}

// Trace prints a message to stdout, if tracing is enabled.
func (c stdoutchn) Trace(format string, a ...interface{}) {
	if (c.on & bit_TRACE) > 0 {
		fmt.Printf("%s", cwhgray)
		fmt.Printf(format, a...)
		if format[len(format)-1] != '\n' {
			fmt.Printf("\n")
		}
		fmt.Printf("%s", cnorm)
	}
}

// Printf unconditionally prints a message to stdout.
func (c stdoutchn) Printf(format string, a ...interface{}) {
	fmt.Printf("%s", cwhgray)
	fmt.Printf(format, a...)
	if format[len(format)-1] != '\n' {
		fmt.Printf("\n")
	}
	fmt.Printf("%s", cnorm)
}

func (c *stdoutchn) TestEnable(name string) {
	dbg := os.Getenv("DEBUG")
	c.on = bit_ERROR | bit_WARNING
	if dbg == "" {
		return
	} else if dbg == "+all" { // easy check: all channels on?
		c.on = 0xffffffff
		return
	}
	// channel names are separated by ';'.
	channels := strings.Split(dbg, ";")
	for _, chn := range channels {
		// figure out which channel they're talking about, the LHS of "a=..."
		equals := strings.SplitN(chn, "=", 2)
		if len(equals) != 2 {
			fmt.Fprintf(os.Stderr, "msg channel: cannot parse '%s'\n", chn)
			return
		}
		chname := strings.TrimSpace(equals[0])
		if chname != name { // not our channel?
			continue
		}

		// now iterate through all the subchannels they want to work with.
		subchan := strings.Split(equals[1], ",")
		for _, sc := range subchan {
			switch strings.ToLower(strings.TrimSpace(sc)) {
			case "+all":
				c.on |= bit_TRACE | bit_WARNING | bit_ERROR
			case "+trace":
				c.on |= bit_TRACE
			case "+warning":
				fallthrough
			case "+warn":
				c.on |= bit_WARNING
			case "+err":
				fallthrough
			case "+error":
				c.on |= bit_ERROR
			case "-all":
				c.on &= 0x0
			case "-trace":
				c.on &= ^bit_TRACE
			case "-warning":
				fallthrough
			case "-warn":
				c.on &= ^bit_WARNING
			case "-err":
				fallthrough
			case "-error":
				c.on &= ^bit_ERROR
			}
		}
	}
}

func StdChan(name string) Channel {
	var rv stdoutchn
	rv.TestEnable(name)
	return rv
}
