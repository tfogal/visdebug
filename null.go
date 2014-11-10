package main

import (
  "./debug"
  "github.com/tfogal/ptrace"
)

// Null is like MallocTrace, but does no prints.
type Null struct {
  BaseEvent
  alloc allocation
  maddr uintptr
  faddr uintptr
}

func (n *Null) malloc(inferior *ptrace.Tracee,
                      bp debug.Breakpoint) error {
  var stk x86_64
  // figure out where the caller is and set a BP there.
  retaddr := stk.RetAddr(inferior)

  if err := n.AddBP(inferior, retaddr, n.mallocret) ; err != nil {
    return err
  }
  return nil
}

func (n *Null) mallocret(inferior *ptrace.Tracee,
                         bp debug.Breakpoint) error {
  // re-insert our BP for malloc.
  if err := n.AddBP(inferior, n.maddr, n.malloc) ; err != nil {
    return err
  }
  return nil
}

func (n *Null) free(inferior *ptrace.Tracee,
                            bp debug.Breakpoint) error {
  var stk x86_64
  // make sure this BP gets re-added when we come back.
  // I do not understand why this needs the 'Top' variant, but it does...
  raddr := uintptr(stk.RetAddrTop(inferior))
  if err := n.AddBP(inferior, raddr, n.freeret) ; err != nil {
    return err
  }

  return nil
}

func (n *Null) freeret(inferior *ptrace.Tracee,
                       bp debug.Breakpoint) error {
  if err := n.AddBP(inferior, n.faddr, n.free) ; err != nil {
    return err
  }

  return nil
}

func (n *Null) Setup(inferior *ptrace.Tracee) error {
  if err := n.BaseEvent.Setup(inferior) ; err != nil {
    return err
  }

  n.faddr = symbol("free", globals.symbols).Address()
  n.maddr = symbol("malloc", globals.symbols).Address()
  assert(n.faddr != 0x0)
  assert(n.maddr != 0x0)

  if err := n.AddBP(inferior, n.maddr, n.malloc) ; err != nil {
    return err
  }
  if err := n.AddBP(inferior, n.faddr, n.free) ; err != nil {
    return err
  }
  return nil
}

func (n *Null) Close(*ptrace.Tracee) error {
  return nil
}
