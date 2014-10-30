/* This defines an InferiorEvent implementation that changes all allocations to
 * be aligned to page boundaries.  This can help expose bugs (invalid memory
 * handling) in the application. */ 
package main

import(
  "fmt"
  "./msg"
  "./debug"
  "github.com/tfogal/ptrace"
)

var aach = msg.StdChan()

type AlignAlloc struct {
  BaseEvent
  length uint
  length_orig uint
  maddr uintptr // the address of 'malloc'
  faddr uintptr // the address of 'free'
  alloc map[uintptr]allocation
}

func (aa *AlignAlloc) malloc(inferior *ptrace.Tracee,
                             bp debug.Breakpoint) error {
  // record the length.
  var stk x86_64
  aa.length = uint(stk.Arg1(inferior))
  aa.length_orig = aa.length

  // "upgrade" the allocation size to align to a page boundary
  if ((4096-1) & aa.length) != 0 {
    aa.length = uint(int64(aa.length + 4096) & ^(4096-1))
    if err := stk.SetArg1(inferior, uint64(aa.length)) ; err != nil {
      return err
    }
  }

  // jump instead to our special version/implementation of malloc.
  tjfmalloc := symbol("__tjfmalloc", globals.symbols)
  assert(tjfmalloc != nil) // you forgot to setup_tjfmalloc, if so.

  if err := inferior.SetIPtr(tjfmalloc.Address()) ; err != nil {
    return err
  }

  // figure out where the caller is and set a BP there.
  retaddr := stk.RetAddr(inferior)

  if err := aa.AddBP(inferior, retaddr, aa.mallocret) ; err != nil {
    return err
  }
  return nil
}

func (aa *AlignAlloc) mallocret(inferior *ptrace.Tracee,
                                bp debug.Breakpoint) error {
  // re-insert malloc BP.
  if err := aa.AddBP(inferior, aa.maddr, aa.malloc) ; err != nil {
    return err
  }

  var stk x86_64
  // reset the correct argument, in case it's reused for something else
  if err := stk.SetArg1(inferior, uint64(aa.length_orig)) ; err != nil {
    return err
  }

  base := uintptr(stk.RetVal(inferior))
  aach.Trace("allocation(%d [%d]) -> 0x%0x\n", aa.length_orig, aa.length, base)

  // our modified allocation disallowed access.. let's re-enable such access
  // now.
  // At some point, we might want to use a new tjfmalloc that just aligns the
  // allocation, instead of aligns+denies write access.
  if err := allow(inferior, base, aa.length, whereis(inferior)) ; err != nil {
    return fmt.Errorf("cannot allow allocation 0x%x: %v", base, err)
  }
  alc := allocation{length: aa.length_orig, lpage: uint64(aa.length), base:base}

  aa.alloc[base] = alc
  return nil
}

func (aa *AlignAlloc) free(inferior *ptrace.Tracee,
                           bp debug.Breakpoint) error {
  var stk x86_64
  // make sure this BP gets re-added when we come back.
  // Don't know why this needs the 'Top' variant.  But it does.
  raddr := uintptr(stk.RetAddrTop(inferior))
  if err := aa.AddBP(inferior, raddr, aa.freeret) ; err != nil {
    return err
  }

  // get the thing that is being freed.
  ptr := uintptr(stk.Arg1(inferior))
  aach.Trace("free(0x%x)\n", ptr)

  // look up that allocation info.
  alc := aa.alloc[ptr]
  err := deny(inferior, ptr, uint(alc.lpage), whereis(inferior))
  if err != nil {
    return fmt.Errorf("cannot deny 0x%x: %v", ptr, err)
  }

  return nil
}

// re-inserts the breakpoint for 'free'.
func (aa *AlignAlloc) freeret(inferior *ptrace.Tracee,
                              bp debug.Breakpoint) error {
  if err := aa.AddBP(inferior, aa.faddr, aa.free) ; err != nil {
    return err
  }
  return nil
}

func (aa *AlignAlloc) Setup(inferior *ptrace.Tracee) error {
  if err := aa.BaseEvent.Setup(inferior) ; err != nil {
    return err
  }

  aa.alloc = make(map[uintptr]allocation)
  assert(symbol("malloc", globals.symbols) != nil) // no symbol table loaded??
  aa.maddr = symbol("malloc", globals.symbols).Address()
  aa.faddr = symbol("free", globals.symbols).Address()

  if err := aa.AddBP(inferior, aa.maddr, aa.malloc) ; err != nil {
    return err
  }

  if err := aa.AddBP(inferior, aa.faddr, aa.free) ; err != nil {
    return err
  }

  return nil
}
