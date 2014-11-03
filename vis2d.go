/* This defines a 'vis2d' InferiorEvent handler.  This handler tracks all the
 * allocations in the program, and when a 2D one is made, it will visualize
 * that result. */
package main

import(
  "fmt"
  "unsafe"
  "./debug"
  "./gfx"
  "./msg"
  "code.google.com/p/rsc.x86/x86asm"
  "github.com/tfogal/ptrace"
)

type field2 struct {
  gsfield gfx.Scalar2D
  data []float32
  dims [2]uint
  alloc allocation
  ignore bool
}

type visualmem2D struct {
  BaseEvent
  fields map[uintptr]field2
  tjfmalloc uintptr // address of 'tjfmalloc' function.
  maddr uintptr // address of 'malloc' function.
  faddr uintptr // address of 'free' function.
  // for the most recent allocation. always points at fields[x].alloc
  // for some x.
  lastcess *allocation
}

var v2d = msg.StdChan()

/*
func (v visualmem2D) String() string {
  return fmt.Sprintf("visual mem: %v %v", v.alloc, v.dims)
}
*/

// called when a 'malloc' breakpoint is hit.
func (v *visualmem2D) malloc(inferior *ptrace.Tracee,
                             bp debug.Breakpoint) error {
  // record the length.
  var stk x86_64
  fld := field2{alloc: allocation{length: uint(stk.Arg1(inferior))}}
  fld.ignore = false
  if fld.alloc.length < globals.minsize {
    fld.ignore = true
  }
  fld.alloc.lpage = uint64(fld.alloc.length)

  // "upgrade" the size of the allocation so that it always ends on a
  // page boundary.
  if !fld.ignore && ((4096-1) & fld.alloc.length) != 0 {
    fld.alloc.lpage = uint64(int64(fld.alloc.length + 4096) & ^(4096-1))
    inject.Trace("upgrading %d-byte allocation to %d bytes\n",
                 uint(stk.Arg1(inferior)), fld.alloc.lpage)
    if err := stk.SetArg1(inferior, fld.alloc.lpage) ; err != nil {
      return fmt.Errorf("error bumping %d-byte alloc up to %d bytes: %v\n",
                        fld.alloc.length, fld.alloc.lpage, err)
    }
  }
  // we don't know the base address yet.  make one up.
  v.fields[0x0] = fld

  // figure out where the caller is and set a BP there.
  retaddr := stk.RetAddr(inferior)

  if err := v.AddBP(inferior, retaddr, v.mallocret) ; err != nil {
    return err
  }

  // and finally jump to our special malloc instead of the standard one.
  if !fld.ignore {
    if err := inferior.SetIPtr(v.tjfmalloc) ; err != nil {
      return err
    }
  }
  return nil
}

func (v *visualmem2D) mallocret(inferior *ptrace.Tracee,
                                bp debug.Breakpoint) error {
  // when we get to the caller, read the malloc call's retval
  var stack x86_64
  //fld := &v.fields[len(v.fields)-1]
  fld := v.fields[0x0]
  fld.alloc.base = uintptr(stack.RetVal(inferior))
  delete(v.fields, 0x0) // drop it.  we'll re-add w/ correct addr at end.

  v2d.Trace("malloc(%d) -> 0x%0x\n", fld.alloc.length, fld.alloc.base)
/*
  if fld.ignore {
    v2d.Trace("Field told us it doesn't matter.  Dropping it...")
    v.fields = v.fields[0:len(v.fields)-1]
  }
*/

  // and re-insert our BP for malloc.
  if err := v.AddBP(inferior, v.maddr, v.malloc) ; err != nil {
    return err
  }

  // We hacked the argument to 'upgrade' it to a page size.  It's probably a
  // dead value, but update it just to be certain we don't make any
  // inferior-visible changes.
  var stk x86_64
  if err := stk.SetArg1(inferior, uint64(fld.alloc.length)) ; err != nil {
    return err
  }

  if !fld.ignore {
    // add a watch for that memory.  This will protect it, even though
    // it's already protected due to how our allocation works, but that
    // shouldn't hurt.
    if err := v.AddWatch(inferior, fld.alloc, v.access) ; err != nil {
      return err
    }
    v2d.Trace("added watch for %v", fld.alloc)

    // allocate stuff we'll use for vis.
    fld.gsfield = gfx.ScalarField2D()
    if err := fld.gsfield.Pre() ; err != nil {
      return err
    }
    var f32 float32
    fld.data = make([]float32, fld.alloc.length / uint(unsafe.Sizeof(f32)))
    v.fields[fld.alloc.base] = fld
  }
  
  return nil
}

// Called when we have segfaulted due to the application program accessing
// memory we are interested in.
func (v *visualmem2D) access(inferior *ptrace.Tracee, pages allocation) error {
  v2d.Trace("inferior accessed %v", pages)
  // get rid of the segv, so execution will correctly continue when we're done.
  if err := inferior.ClearSignal() ; err != nil {
    return err
  }

  // 'accessret' needs this to know *which* access it is reinstating.
  fld := v.fields[pages.base]
  v.lastcess = &fld.alloc

  v2d.Trace("access of 0x%x+%d by 0x%x\n", fld.alloc.base, fld.alloc.length,
            whereis(inferior))

  // NOTE we need to do the bounds up here, BEFORE we 'AddBP' below!  That's
  // because 'bounds' can do a bit of execution, and if we hit something we've
  // set up here then we'll be in bad shape...
  assert(globals.program != "")
  dims, err := bounds(globals.program, inferior)
  if err != nil {
    // note it, but ignore it.  this happens sometimes, e.g. when accessing
    // data outside of a loop.
    v2d.Warning("error getting bounds: %v\n", err)
  } else {
    if len(dims) >= 2 {
      copy(fld.dims[0:2], dims[0:2])
    }
    v2d.Trace("bounds: %v\n", dims)
  }

  var stk x86_64
  // By my reasoning, we are in the middle of a function (we just came back
  // from a call!).. but experience and testing shows that the stack is almost
  // always setup so that we are in a prologue/epilogue...
  raddr := stk.RetAddrTop(inferior)
  v2d.Trace("want to add BP @ 0x%x", raddr)
  if err := v.AddBP(inferior, raddr, v.accessret) ; err != nil {
    // okay... try again assuming we are not in a prologue/epilogue.
    raddr = stk.RetAddrMid(inferior)
    v2d.Warning("bad return address. will try @ 0x%x", raddr)
    if err := v.AddBP(inferior, raddr, v.accessret) ; err != nil {
      // *still* no luck.  Okay, just search for a 'ret' insn, but from the top
      // of the function we are in now, not the current iptr
      symbol, err := where(inferior)
      if err != nil {
        return err
      }
      v2d.Warning("That failed too; searching for ret in %v", symbol)
      ret, err := find_opcode(x86asm.RET, inferior, symbol.Address())
      if err != nil {
        return fmt.Errorf("did not find RET in %v: %v", symbol, err)
      }
      if err := v.AddBP(inferior, ret, v.accessret) ; err != nil {
        return fmt.Errorf("all methods for finding a good breakpoint to " +
                          "re-enable protection failed!  last one: %v\n", err)
      }
      v2d.Trace("(ret insn) set our BP (for DENY) at 0x%x", ret)
    }
  }
  v.fields[fld.alloc.base] = fld

  return nil
}

// Called when we're finished with some code that accessed our data of
// interest.  We need to re-enable memory protection here.  And maybe do some
// visualization, which is, ya know, our whole purpose here and all.
func (v *visualmem2D) accessret(inferior *ptrace.Tracee,
                                bp debug.Breakpoint) error {
  v2d.Trace("Re-enabling protection for something.")
  if v.lastcess == nil {
    // This means that we tried to have *two* accessrets in the same function.
    // That definitely means things are broken.  We need to keep a *list* of
    // protections we want to re-enable, not a single thing.
    v2d.Warning("Don't know last access.  Broken access detection!")
    v2d.Warning("It's likely there is some memory that we *were* watching " +
                "but are no longer; we will miss some updates!")
    return nil
  }
  _, err := v.pages(v.lastcess.base)
  if err != nil {
    v2d.Trace("allocation %v was removed, ignoring.", v.lastcess)
    return nil
  }
  v2d.Trace("Adding watch (enabling protection) for %v", *v.lastcess)
  if err := v.AddWatch(inferior, *v.lastcess, v.access) ; err != nil {
    return err
  }

  //fld := v.find_field_by_page(*v.lastcess)
  fld := v.fields[v.lastcess.base]
  //assert(fld != field2{}) // what inserted the BP that got us here, if so?
  if len(fld.dims) == 2 && fld.dims[0] > 0 && fld.dims[1] > 0 {
    // 'Read' needs []byte memory, annoyingly.
    bslice := castf32b(fld.data)
    if err := inferior.Read(fld.alloc.base, bslice) ; err != nil {
      return err
    }
    mx := maxf(fld.data)
    v2d.Trace("calculated max of: %v\n", mx)
    fld.gsfield.Render(fld.data, fld.dims[0:2], mx)
  }

  // reset the last access, so we don't accidentally reuse it.
  v.lastcess = nil
  return nil
}

func (v *visualmem2D) pages(addr uintptr) (allocation, error) {
  for _, fld := range v.fields {
    if addr == fld.alloc.base {
      return fld.alloc, nil
    }
  }
  return allocation{}, fmt.Errorf("allocation 0x%x not found", addr)
}

func (v *visualmem2D) free(inferior *ptrace.Tracee, bp debug.Breakpoint) error {
  var stk x86_64
  freearg := uintptr(stk.Arg1(inferior)) // what they're freeing
  alc, err := v.pages(freearg) // figure out pages from address
  v2d.Trace("free(0x%0x) [ours: %v]", freearg, err==nil)
  if err != nil {
    // Not necessarily an error.  Could be memory we decided not to instrument.
    v2d.Trace("allocation 0x%x not found; not instrumented?", freearg)
    return nil
  }
  assert(alc.base == freearg)
  if err := v.DropWatch(inferior, alc) ; err != nil {
    v2d.Warning("We weren't watching %v... (%v)\n", alc, err)
    return nil
  }
  delete(v.fields, alc.base)

  // find where free returns to; we'll call ourselves there to reinsert the
  // 'free' BP.
  raddr := uintptr(stk.RetAddrTop(inferior))
  if err := v.AddBP(inferior, raddr, v.freeret) ; err != nil {
    return fmt.Errorf("error inserting freeret bp@0x%x: %v", raddr, err)
  }
  return nil
}

func (v *visualmem2D) freeret(inferior *ptrace.Tracee,
                              bp debug.Breakpoint) error {
  v2d.Trace("re-adding 'free' (0x%x) bp", v.faddr)
  if err := v.AddBP(inferior, v.faddr, v.free) ; err != nil {
    return fmt.Errorf("error reinserting 'free' BP@0x%x: %v", v.faddr, err)
  }
  return nil
}

func (v *visualmem2D) Setup(inferior *ptrace.Tracee) error {
  if err := v.BaseEvent.Setup(inferior) ; err != nil {
    return err
  }

  v.fields = make(map[uintptr]field2)

  tjfmalloc := symbol("__tjfmalloc", globals.symbols)
  assert(tjfmalloc != nil)
  v.tjfmalloc = tjfmalloc.Address()

  mloc := symbol("malloc", globals.symbols)
  assert(mloc != nil)
  v.maddr = mloc.Address()

  floc := symbol("free", globals.symbols)
  assert(floc != nil)
  v.faddr = floc.Address()

  // malloc will tell us what allocations we will care about.
  if err := v.AddBP(inferior, v.maddr, v.malloc) ; err != nil {
    return err
  }

  // free means we can/should stop watching that memory.
  if err := v.AddBP(inferior, v.faddr, v.free) ; err != nil {
    return err
  }

  return nil
}

func (v *visualmem2D) Close(inferior *ptrace.Tracee) error {
  for _, fld := range v.fields {
    if fld.gsfield != nil {
      fld.gsfield.Post()
    }
  }
  v.fields = nil
  return nil
}
