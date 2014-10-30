package main

import (
  "errors"
  "fmt"
  "./debug"
  "github.com/tfogal/ptrace"
)

// Malloc trace is an InferiorEvent implementation that simply traces
// every malloc call in the given process, noting the address and size
// that it occurs.
type MallocTrace struct {
  BaseEvent
  alloc allocation
}

func (mt *MallocTrace) malloc(inferior *ptrace.Tracee,
                              bp debug.Breakpoint) error {
  // record the length.
  var stk x86_64
  mt.alloc.length = uint(stk.Arg1(inferior))

  // remove the BP so we can get run enough to return back to the caller
  if err := mt.DropBP(inferior, bp.Address) ; err != nil {
    return err
  }
  // figure out where the caller is and set a BP there.
  retaddr := stk.RetAddr(inferior)

  if err := mt.AddBP(inferior, retaddr, mt.mallocret) ; err != nil {
    return err
  }
  return nil
}

func (mt *MallocTrace) mallocret(inferior *ptrace.Tracee,
                                 bp debug.Breakpoint) error {
  // when we get to the caller, read the BP's retval
  var stack x86_64
  mt.alloc.base = uintptr(stack.RetVal(inferior))
  // do our actual work: printing out what happens.
  fmt.Printf("malloc(%d) -> 0x%0x\n", mt.alloc.length, mt.alloc.base)

  // get rid of this BP ...
  if err := mt.DropBP(inferior, bp.Address) ; err != nil {
    return err
  }
  mloc := symbol("malloc", globals.symbols)
  assert(mloc != nil)

  // and re-insert our BP for malloc.
  if err := mt.AddBP(inferior, mloc.Address(), mt.malloc) ; err != nil {
    return err
  }
  return nil
}

func (mt *MallocTrace) Setup(inferior *ptrace.Tracee) error {
  if err := mt.BaseEvent.Setup(inferior) ; err != nil {
    return err
  }

  symmalloc := symbol("malloc", globals.symbols)
  if symmalloc == nil {
    return errors.New("'malloc' not available; error reading symtab?")
  }

  if err := mt.AddBP(inferior, symmalloc.Address(), mt.malloc) ; err != nil {
    return err
  }
  return nil
}
