/* This defines a 'vis2d' InferiorEvent handler.  This handler tracks all the
 * allocations in the program, and when a 2D one is made, it will visualize
 * that result. */
package main

import(
  "fmt"
  "unsafe"
  "./cfg"
  "./debug"
  "./gfx"
  "./msg"
  "code.google.com/p/rsc.x86/x86asm"
  "github.com/tfogal/ptrace"
)

var v2d = msg.StdChan()

type fieldstate uint
const(
  stnull = fieldstate(0)
  stmalloc = iota
  stmallocret
  stfree
  stallow
  sthdr
  stdeny
)

type field2 struct {
  gsfield gfx.Scalar2D
  data []float32
  dims []uint
  alloc allocation
  state fieldstate
}

type visualmem2D struct {
  BaseEvent
  tjfmalloc uintptr // address of 'tjfmalloc' function.
  maddr uintptr     // address of 'malloc' function.
  faddr uintptr     // address of 'free' function.
  fields map[uintptr]field2
  // a slice of pointers at field[x].allocs that we need to re-enable when this
  // function exits.
  todeny map[uintptr]*allocation
}

func (v *visualmem2D) destroy(fldaddr uintptr) {
  // first, make sure there's nothing to for that field.
  delete(v.todeny, v.fields[fldaddr].alloc.base)
  delete(v.fields, fldaddr)
}

// called when a 'malloc' breakpoint is hit.
func (v *visualmem2D) malloc(inferior *ptrace.Tracee,
                             bp debug.Breakpoint) error {
  var stk x86_64
  // figure out where the caller is, plus set a BP there.
  retaddr := stk.RetAddr(inferior)
  if err := v.AddBP(inferior, retaddr, v.mallocret) ; err != nil {
    return fmt.Errorf("cannot add mallocret bp@0x%x: %v", retaddr, err)
  }

  // does that caller make sense?  we don't care if glibc allocs memory.
  {
    symbol, err := find_function(retaddr)
    if err != nil {
      v2d.Warning("can't find fqn from 0x%x: %v", retaddr, err)
    } else {
      if !user_symbol(symbol.Name()) {
        v2d.Trace("Allocating memory in %s?  We don't care.", symbol.Name())
        return nil
      }
      v2d.Trace("bp when we return from %s", symbol.Name())
    }
  }

  // record the length.
  fld := field2{alloc: allocation{length: uint(stk.Arg1(inferior))},
                state: stmalloc}
  if fld.alloc.length < globals.minsize {
    return nil
  }
  fld.alloc.lpage = uint64(fld.alloc.length)

  // "upgrade" the size of the allocation so that it always ends on a
  // page boundary.
  if ((4096-1) & fld.alloc.length) != 0 {
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

  // and finally jump to our special malloc instead of the standard one.
  if err := inferior.SetIPtr(v.tjfmalloc) ; err != nil {
    return err
  }

  return nil
}

func (v *visualmem2D) mallocret(inferior *ptrace.Tracee,
                                bp debug.Breakpoint) error {
  // re-insert our BP for malloc.
  if err := v.AddBP(inferior, v.maddr, v.malloc) ; err != nil {
    return fmt.Errorf("adding malloc bp@0x%x: %v", v.maddr, err)
  }

  // we didn't know the address yet, so we put it at 0x0.
  fld := v.fields[0x0]
  delete(v.fields, 0x0) // we'll re-add with a better addr, if appropriate.
  if stnull == fld.state { // then we didn't create a state for this.  ignore.
    return nil
  }

  var stk x86_64
  // when we get to the caller, read the malloc call's retval
  fld.alloc.base = uintptr(stk.RetVal(inferior))

  v2d.Trace("malloc(%d) -> 0x%x", fld.alloc.length, fld.alloc.base)
  assert(fld.alloc.base & 0xfff == 0x0) // memory is page-aligned.

  // We hacked the argument to 'upgrade' it to a page size.  It's probably a
  // dead value, but update it just to be certain we don't make any
  // inferior-visible changes.
  if err := stk.SetArg1(inferior, uint64(fld.alloc.length)) ; err != nil {
    return err
  }

  // add a watch for that memory.  This will protect it, even though
  // it's already protected due to how our allocation works, but that
  // shouldn't hurt.
  if err := v.AddWatch(inferior, fld.alloc, v.access) ; err != nil {
    return err
  }
  v2d.Trace("added watch for %v", fld.alloc)
  delete(v.todeny, fld.alloc.base)

  // allocate stuff we'll use for vis.
  fld.gsfield = gfx.ScalarField2D()
  if err := fld.gsfield.Pre() ; err != nil {
    return err
  }
  var f32 float32
  fld.data = make([]float32, fld.alloc.length / uint(unsafe.Sizeof(f32)))
  v.fields[fld.alloc.base] = fld

  return nil
}

// adds an allocation to our list of 'we need to re-enable access detection on
// this'.
func (v *visualmem2D) add_blocker(alc *allocation) {
  if v.todeny == nil {
    v.todeny = make(map[uintptr]*allocation)
  }

  assert(v.todeny[alc.base] == nil) // i.e. not there already.
  v.todeny[alc.base] = alc
}

// Called when we have segfaulted due to the application program accessing
// memory we are interested in.
func (v *visualmem2D) access(inferior *ptrace.Tracee, pages allocation) error {
  v2d.Trace("inferior accessed %v at 0x%x", pages, whereis(inferior))
  // get rid of the segv, so execution will correctly continue when we're done.
  if err := inferior.ClearSignal() ; err != nil {
    return err
  }

  // 'accessret' needs this to know *which* access it is reinstating.
  fld := v.fields[pages.base]
  v.add_blocker(&fld.alloc)

  // Okay, BPs are set for the loop header.  Now also figure out where we're
  // returning to, so we can set a BP there && enable access detection again.
  var stk x86_64
  // By my reasoning, we are in the middle of a function (we just came back
  // from a call!).. but experience and testing shows that the stack is almost
  // always setup such that we are in a prologue/epilogue...
  raddr := stk.RetAddrTop(inferior)
  v2d.Trace("want to add re-enable protection @ 0x%x", raddr)
  if err := v.AddBP(inferior, raddr, v.accessret) ; err != nil {
    // okay... try again assuming we are not in a prologue/epilogue.
    raddr = stk.RetAddrMid(inferior)
    v2d.Warning("bad return address (%v). will try @ 0x%x", err, raddr)
    if err := v.AddBP(inferior, raddr, v.accessret) ; err != nil {
      // *still* no luck.  Okay, just search for a 'ret' insn, but from the top
      // of the function we are in now, not the current iptr
      symbol, err := where(inferior)
      if err != nil {
        return fmt.Errorf("dunno where are: %v", err)
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

  assert(globals.program != "")
  // There are *three* exit points from this state.
  //   - the memory is freed
  //   - we hit a loop header BB that bounds our current BB.
  //   - we return / leave the function
  // A BP for 'free' should already be set.  Next we'll set a BP for the loop
  // header.
  symbol, err := where(inferior)
  if err != nil {
    return err
  }
  // If a library function like 'memset' created the access, just ignore it; we
  // won't get any information out of library functions.
  if !user_symbol(symbol.Name()) {
    return nil
  }
  graph := cfg.FromAddress(globals.program, symbol.Address())
  if graph == nil {
    return fmt.Errorf("could not compute CFG for %v", symbol)
  }
  if rn := root_node(graph, symbol) ; rn != nil {
    cfg.Analyze(rn)
  }
  bb, err := basic_block(graph, whereis(inferior))
  if err != nil {
    return fmt.Errorf("Beware of grue: %v", err) // don't know where we are?
  }
  // Initialize our dims.
  fld.dims = make([]uint, 0)
  fld.state = stallow
  for _, hdr := range bb.Headers {
    v2d.Trace("inserting header BP @ 0x%x", hdr.Addr)
    if v.AddBP(inferior, hdr.Addr, v.header) ; err != nil {
      return fmt.Errorf("BP at loop header (0x%x): %v", hdr.Addr, err)
    }
  }
  v.fields[fld.alloc.base] = fld

  return nil
}

// Hit a loop header basic block.
func (v *visualmem2D) header(inferior *ptrace.Tracee,
                             bp debug.Breakpoint) error {
  v2d.Trace("header BP (%v) hit", bp)

  // There are a few exit paths from this node.
  //   - free of the memory we have here
  //   - the return address of the current function
  //   - higher round of header info.
  // 'free' should already be taken care of.  The return address breakpoint
  // should have been created in 'access', which had to come before this.
  // So: see if we can find any loop headers for us, and break on that.
  symbol, err := where(inferior)
  if err != nil {
    return err
  }
  // we had to come through 'access' to get here, and that would not have led
  // us here unless the current symbol was a user_symbol.
  assert(user_symbol(symbol.Name()))
  graph := cfg.FromAddress(globals.program, symbol.Address())
  if graph == nil {
    return fmt.Errorf("could not compute CFG for %v", symbol)
  }
  if rn := root_node(graph, symbol) ; rn != nil {
    cfg.Analyze(rn)
  }
  bb, err := basic_block(graph, whereis(inferior))
  if err != nil {
    return fmt.Errorf("Beware of grue: %v", err) // don't know where we are?
  }
  assert(bb.LoopHeader()) // if this isn't a loop header, wtf?

  assert(whereis(inferior) == bb.Addr)
  // we'd like to insert our BP first.  But that could muck up symexec and
  // execution in general!  so first lets do our actual work: one iteration's
  // worth of identifying loop bounds.  we only do one iteration; when we're
  // done, we'll set a BP so that we'll get called again if there are further
  // iterations.
  insn_regs, err := symexec(inferior, bb.Addr)
  if err != nil {
    return err
  }
  ixn, cmpaddr, err := find_2arg([]x86asm.Op{x86asm.CMP}, inferior, bb.Addr)
  if err != nil {
    return fmt.Errorf("cannot find 'cmp' insn in bb@0x%x: %v", bb.Addr, err)
  }
  // this is a little sketch, because we shouldn't be letting the inferior
  // execute in any of these.  but it should just be a few instructions, and
  // there's little likelihood it will hit a different BB or access blocked mem
  if err := debug.WaitUntil(inferior, cmpaddr) ; err != nil {
    return fmt.Errorf("executing in 'header' (sketch!): %v", err)
  }

  rf := rfaddr(insn_regs, cmpaddr)
  assert(rf != nil) // we just executed up until the CMP. now it's not there?

  values, err := readargs(ixn, rf, symbol.Name(), inferior)
  if err != nil {
    return err
  }
  larger := maxvalue(values)
  for j, fld := range v.fields {
    if fld.state == stallow {
      fld.state = sthdr
    }
    if fld.state == sthdr {
      fld.dims = append(fld.dims, uint(larger))
    }
    v.fields[j] = fld
  }

  // loop for any loop headers and set breakpoints there that will in turn call
  // us again: this is how we loop through the headers.
  for _, hdr := range bb.Headers {
    v2d.Trace("inserting header BP @ 0x%x", hdr.Addr)
    if v.AddBP(inferior, hdr.Addr, v.header) ; err != nil {
      return fmt.Errorf("BP at loop header (0x%x): %v", hdr.Addr, err)
    }
  }

  return nil
}

func (v *visualmem2D) vis(inferior *ptrace.Tracee, addr uintptr) error {
  fld := v.fields[addr]
  assert(fld.gsfield != nil) // i.e. this is a valid field.

  if fld.dims == nil {
    v2d.Warning("dims is nil, ignoring")
    return nil
  }
  if len(fld.dims) != 2 {
    v2d.Warning("dims array length is not 2 (%d), ignoring", len(fld.dims))
    return nil
  }
  if fld.dims[0]*fld.dims[1] <= 0 {
    v2d.Warning("dims not positive (%dx%d)", fld.dims[0], fld.dims[1])
    return nil
  }
  if fld.dims != nil && len(fld.dims) == 2 && fld.dims[0]*fld.dims[1] > 0 {
    // 'Read' needs []byte memory, annoyingly.
    bslice := castf32b(fld.data)
    assert(fld.data != nil)
    if err := inferior.Read(fld.alloc.base, bslice) ; err != nil {
      wo := addr_where(inferior.PID(), fld.alloc.base)
      fmt.Printf("%v is in '%s'\n", fld.alloc, wo)
      return fmt.Errorf("read failed: %v", err)
    }
    mx := maxf(fld.data)
    v2d.Trace("calculated max of: %v\n", mx)
    fld.gsfield.Render(fld.data, fld.dims, mx)
  }

  return nil
}

// Called when we're finished with some code that accessed our data of
// interest.  We need to re-enable memory protection here.  And maybe do some
// visualization, which is, ya know, our whole purpose here and all.
func (v *visualmem2D) accessret(inferior *ptrace.Tracee,
                                bp debug.Breakpoint) error {
  if v.todeny == nil {
    v2d.Warning("Nothing to re-enable.  This means that the current function" +
                " free()d all memory that it accessed.  Unlikely but possible.")
    return nil
  }
  v2d.Trace("Re-enabling protection for %d allocs.", len(v.todeny))

  for _, alc := range v.todeny {
    _, err := v.pages(alc.base)
    if err != nil {
      v2d.Trace("allocation %v was removed, ignoring.", *alc)
      continue
    }

    if err := v.vis(inferior, alc.base) ; err != nil {
      return fmt.Errorf("could not vis %v: %v", alc, err)
    }

    v2d.Trace("Adding watch for %v", *alc)
    if err := v.AddWatch(inferior, *alc, v.access) ; err != nil {
      return err
    }
  }

  // now that we've processed our list, drop it.
  v.todeny = nil

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

  // we don't care about free's return value, but we need to reinsert the BP
  // *somewhere*.
  raddr := uintptr(stk.RetAddrTop(inferior))
  if err := v.AddBP(inferior, raddr, v.freeret) ; err != nil {
    return fmt.Errorf("error inserting freeret bp@0x%x: %v", raddr, err)
  }

  freearg := uintptr(stk.Arg1(inferior)) // what they're freeing
  alc, err := v.pages(freearg) // figure out pages from address
  v2d.Trace("free(0x%x) [ours: %v]", freearg, err==nil)
  if err != nil {
    // Not necessarily an error.  Could be memory we decided not to instrument.
    v2d.Trace("allocation 0x%x not found; not instrumented?", freearg)
    return nil
  }
  assert(alc.base == freearg)
  if err := v.DropWatch(inferior, alc) ; err != nil {
    v2d.Warning("We weren't watching %v... (%v)\n", alc, err)
    return err
  }
  v.destroy(alc.base)

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
    return fmt.Errorf("could not add initial 'malloc' bp: %v", err)
  }

  // free means we can/should stop watching that memory.
  if err := v.AddBP(inferior, v.faddr, v.free) ; err != nil {
    return fmt.Errorf("could not add initial 'free' bp: %v", err)
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
