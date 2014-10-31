package main

import(
  "fmt"
  "./debug"
  "github.com/tfogal/ptrace"
)

type BPcb func(*ptrace.Tracee, debug.Breakpoint) error
type SFcb func(*ptrace.Tracee, allocation) error

// Registers and handles events for an inferior.  The client will register a
// set of breakpoints and regions to watch (i.e. memory protect), and this will
// keep track of the breakpoints and 'watchpoints' for the user.
type InferiorEvent interface {
  // Add initial breakpoints/watchpoints.
  Setup(*ptrace.Tracee) error
  // clean up all our internal resources
  Close(*ptrace.Tracee) error

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

  AddWatch(inf *ptrace.Tracee, addr_range allocation, cb SFcb) error
  DropWatch(*ptrace.Tracee, allocation) error
}

type breakelem struct {
  bp debug.Breakpoint
  cb BPcb
}
type sfelem struct {
  alloc allocation
  cb SFcb
}
type BaseEvent struct {
  // It is silly to create a map of these based on the address, since the
  // address is in the Breakpoint itself.  But we need to be able to remove
  // breakpoints from our list, and you can't shrink a slice.
  bp map[uintptr]breakelem
  sf map[uintptr]sfelem
}

func (be *BaseEvent) Setup(*ptrace.Tracee) error {
  be.bp = make(map[uintptr]breakelem)
  be.sf = make(map[uintptr]sfelem)
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

func find_sf(addrs map[uintptr]sfelem, access uintptr) (sfelem, error) {
  for _, fault := range addrs {
    alc := fault.alloc
    if alc.begin() <= access && access <= alc.end() {
      return fault, nil
    }
  }
  return sfelem{}, fmt.Errorf("allocation 0x%0x not found", access)
}

func (be *BaseEvent) Segfault(inferior *ptrace.Tracee, access uintptr) error {
  sfinfo, err := find_sf(be.sf, access)
  if err != nil {
    return fmt.Errorf("segfault at 0x%x (%v)", access, err)
  }

  if err := be.DropWatch(inferior, sfinfo.alloc) ; err != nil {
    return err
  }

  if err := sfinfo.cb(inferior, sfinfo.alloc) ; err != nil {
    return err
  }
  return nil
}

func (be *BaseEvent) AddWatch(inferior *ptrace.Tracee, pages allocation,
                              cb SFcb) error {
  iptr, err := inferior.GetIPtr()
  if err != nil {
    return fmt.Errorf("don't know where we are: %v", err)
  }
  err = deny(inferior, pages.base, uint(pages.lpage), iptr)
  if err != nil {
    return fmt.Errorf("can't deny 0x%x+%d: %v", pages.base, pages.lpage, err)
  }

  be.sf[pages.base] = sfelem{alloc: pages, cb: cb}
  return nil
}

func (be *BaseEvent) DropWatch(inferior *ptrace.Tracee,
                               pages allocation) error {
  err := allow(inferior, pages.base, uint(pages.lpage), whereis(inferior))
  if err != nil {
    return fmt.Errorf("can't allow 0x%x+%d: %v", pages.base, pages.lpage, err)
  }
  delete(be.sf, pages.base)
  return nil
}
