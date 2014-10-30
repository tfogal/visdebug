package main

import(
  "fmt"
  "log"
  "./debug"
  "github.com/tfogal/ptrace"
)

type BPcb func(*ptrace.Tracee, debug.Breakpoint) error

// Registers and handles events for an inferior.  The client will register a
// set of breakpoints and regions to watch (i.e. memory protect), and this will
// keep track of the breakpoints and 'watchpoints' for the user.
type InferiorEvent interface {
  // Add initial breakpoints/watchpoints.
  Setup(inf *ptrace.Tracee) error

  // add a breakpoint at the specified address.
  AddBP(inf *ptrace.Tracee, addr uintptr, cb BPcb) error
  // remove a breakpoint
  DropBP(inf *ptrace.Tracee, addr uintptr) error
  // identify the breakpoint for the given address and call its callback.  Note
  // that this also drops the BP!  make arrangements for it to be reinserted
  // somewhere else if you still need/want it.
  Trap(inf *ptrace.Tracee, address uintptr) error

  // handle a segfault.
  Segfault(inf *ptrace.Tracee, address uintptr) error

/*
  AddWatch(inf *ptrace.Tracee, addr_range allocation,
           cb func(*ptrace.Tracee, allocation) error) error
*/
}

type breakelem struct {
  bp debug.Breakpoint
  cb BPcb
}
type BaseEvent struct {
  // It is silly to create a map of these based on the address, since the
  // address is in the Breakpoint itself.  But we need to be able to remove
  // breakpoints from our list, and you can't shrink a slice.
  bp map[uintptr]breakelem
}

func (be *BaseEvent) Setup(*ptrace.Tracee) error {
  be.bp = make(map[uintptr]breakelem)
  return nil
}

/* for debugging */
func (be *BaseEvent) printBPs() {
  fmt.Println("bps are now:")
  sm := symbol("malloc", globals.symbols).Address()
  sf := symbol("free", globals.symbols).Address()
  for k, v := range be.bp {
    if k == sm {
      fmt.Printf("bp: malloc: %v\n", v.bp)
    } else if k == sf {
      fmt.Printf("bp: free: %v\n", v.bp)
    } else {
      fmt.Printf("bp: 0x%x: %v\n", k, v.bp)
    }
  }
}

func (be *BaseEvent) AddBP(inferior *ptrace.Tracee, addr uintptr,
                           cb BPcb) error {
  bp, err := debug.Break(inferior, addr)
  if err != nil {
    return err
  }
  be.bp[addr] = breakelem{bp: bp, cb: cb}
  return nil
}

func (be *BaseEvent) DropBP(inferior *ptrace.Tracee, addr uintptr) error {
  if err := debug.Unbreak(inferior, be.bp[addr].bp) ; err != nil {
    return err
  }
  // remove the BP from our list.
  delete(be.bp, addr)
  return nil
}

func (be *BaseEvent) Trap(inferior *ptrace.Tracee, addr uintptr) error {
  bpinfo := be.bp[addr]
  // drop the BP.  Execution can't continue otherwise.  If the user wants the
  // breakpoint to be persistent, they need to setup a mechanism by which it
  // will get re-inserted.
  if err := be.DropBP(inferior, addr) ; err != nil {
    return err
  }
  if err := bpinfo.cb(inferior, be.bp[addr].bp) ; err != nil {
    return err
  }
  return nil
}

func (be *BaseEvent) Segfault(inferior *ptrace.Tracee, access uintptr) error {
  log.Fatalf("segfault handler not yet implemented.\n")
  return nil
}
