/* This defines an InferiorEvent implementation that just forwards the arrays
 * it gets to python and runs a user-provided script. */
package main

import (
	"./debug"
	"./msg"
	"code.google.com/p/rsc.x86/x86asm"
	"errors"
	"fmt"
	"github.com/sbinet/go-python"
	"github.com/tfogal/gonpy"
	"github.com/tfogal/ptrace"
	"unsafe"
)

type field struct {
	data   []float32
	dims   []uint
	alloc  allocation
	state  fieldstate
	pydata *python.PyObject
}

type Python struct {
	BaseEvent
	tjfmalloc uintptr           // address of 'tjfmalloc' (aligning alloc)
	maddr     uintptr           // address of 'malloc'
	faddr     uintptr           // address of 'free'
	fields    map[uintptr]field // currently active fields.
	// list of allocations that we'll need to start watching again when the
	// current function exits.  Needs to be a map so we can delete things from it
	// arbitrarily: if the memory is freed before the function exits, for
	// example.
	todeny map[uintptr]*allocation
	module *python.PyObject
	dict   *python.PyObject
}

var pyc = msg.StdChan("pyc")

func (p *Python) vis(inferior *ptrace.Tracee, addr uintptr) error {
	pyc.Trace("using alloc @ 0x%x", addr)
	fld := p.fields[addr]
	assert(fld.data != nil) // i.e. this is a valid field.

	if fld.dims == nil {
		pyc.Warn("dims is nil, ignoring")
		return nil
	}
	for _, d := range fld.dims {
		if d == 0 {
			pyc.Warn("null dimension; don't know how to deal with this.  bailing.")
			return nil
		}
	}

	// 'Read' needs []byte memory, annoyingly.
	bslice := castf32b(fld.data)
	if err := inferior.Read(fld.alloc.base, bslice); err != nil {
		wo := addr_where(inferior.PID(), fld.alloc.base)
		pyc.Trace("%v is in '%s'\n", fld.alloc, wo)
		return fmt.Errorf("read failed: %v", err)
	}

	// 'SimpleNewFromData' needs an []int, we have a []uint.
	idims := make([]int, len(fld.dims))
	for i := range fld.dims {
		idims[i] = int(fld.dims[i])
	}
	assert(len(idims) == len(fld.dims))
	var err error
	fld.pydata, err = gonpy.Array_SimpleNewFromData(uint(len(fld.dims)), idims,
		gonpy.NPY_FLOAT,
		unsafe.Pointer(&fld.data[0]))
	if err != nil {
		return fmt.Errorf("could not create python array: %v", err)
	}

	str := python.PyString_FromString("data")
	python.PyDict_SetItem(p.dict, str, fld.pydata)
	str.Clear()

	if err := python.PyRun_SimpleFile("test.py"); err != nil {
		return err
	}

	return nil
}

func (p *Python) destroy(fldaddr uintptr) {
	delete(p.todeny, p.fields[fldaddr].alloc.base)
	if p.fields[fldaddr].pydata != nil {
		p.fields[fldaddr].pydata.Clear()
	}
	delete(p.fields, fldaddr)
}

// we'll set things up so that this gets called when the simulation mallocs.
func (p *Python) malloc(inferior *ptrace.Tracee, bp debug.Breakpoint) error {
	var stk x86_64
	// set a bp back in the caller, so we can pull out the return address.
	retaddr := stk.RetAddr(inferior)
	if err := p.AddBP(inferior, retaddr, p.mallocret); err != nil {
		return fmt.Errorf("cannot add mallocret bp@0x%x: %v", retaddr, err)
	}

	// does that caller make sense?  we don't care if glibc allocs memory.
	{
		symbol, err := find_function(retaddr)
		if err != nil {
			pyc.Warn("can't find fqn from 0x%x: %v", retaddr, err)
		} else {
			if !user_symbol(symbol.Name()) {
				pyc.Trace("Allocating memory in %s?  We don't care.", symbol.Name())
				return nil
			}
			pyc.Trace("bp when we return from %s", symbol.Name())
		}
	}

	// record the length.
	fld := field{alloc: allocation{length: uint(stk.Arg1(inferior))},
		state: stmalloc}
	if fld.alloc.length < globals.minsize {
		return nil
	}
	fld.alloc.lpage = uint64(fld.alloc.length)

	// we don't want another variable using the same page, because then
	// we would not be able to discern which variable was accessed. so,
	// "upgrade" the size of the allocation so that it always ends on a
	// page boundary.
	if ((4096 - 1) & fld.alloc.length) != 0 {
		fld.alloc.lpage = uint64(int64(fld.alloc.length+4096) & ^(4096 - 1))
		inject.Trace("upgrading %d-byte allocation to %d bytes\n",
			uint(stk.Arg1(inferior)), fld.alloc.lpage)
		if err := stk.SetArg1(inferior, fld.alloc.lpage); err != nil {
			return fmt.Errorf("error bumping %d-byte alloc up to %d bytes: %v\n",
				fld.alloc.length, fld.alloc.lpage, err)
		}
	}

	// we don't know the base address yet.  make one up.
	p.fields[0x0] = fld

	// and finally jump to our special malloc instead of the standard one.
	if err := inferior.SetIPtr(p.tjfmalloc); err != nil {
		return err
	}

	return nil
}

// pre sets up a given field for any visualization we'll need to do.
// guaranteed to be called once before 'vis'.
func (p *Python) pre(fld *field) error {
	var f32 float32
	fld.data = make([]float32, fld.alloc.length/uint(unsafe.Sizeof(f32)))
	return nil
}

func (p *Python) mallocret(inferior *ptrace.Tracee, bp debug.Breakpoint) error {
	// re-insert our BP for malloc.
	if err := p.AddBP(inferior, p.maddr, p.malloc); err != nil {
		return fmt.Errorf("adding malloc bp@0x%x: %v", p.maddr, err)
	}

	// we didn't know the address yet, so we put it at 0x0 back in 'malloc'.
	fld := p.fields[0x0]
	delete(p.fields, 0x0)    // we'll re-add with a better addr, if appropriate.
	if stnull == fld.state { // then we didn't create a state for this.  ignore.
		return nil
	}

	var stk x86_64
	// malloc's return value is the base address of our future vis-able array
	fld.alloc.base = uintptr(stk.RetVal(inferior))

	pyc.Trace("malloc(%d) -> 0x%x", fld.alloc.length, fld.alloc.base)
	assert(fld.alloc.base&0xfff == 0x0) // memory is page-aligned.

	// We hacked the argument to 'upgrade' it to a page size.  It's probably a
	// dead value, but update it just to be certain we don't make any
	// inferior-visible changes.
	if err := stk.SetArg1(inferior, uint64(fld.alloc.length)); err != nil {
		return err
	}

	// add a watch for that memory.  This will protect it, even though
	// it's already protected due to how our allocation works, but that
	// shouldn't hurt.
	if err := p.AddWatch(inferior, fld.alloc, p.access); err != nil {
		return err
	}
	pyc.Trace("added watch for %v", fld.alloc)
	delete(p.todeny, fld.alloc.base)

	// allocate stuff we'll use for vis.
	if err := p.pre(&fld); err != nil {
		return err
	}

	p.fields[fld.alloc.base] = fld

	return nil
}

func (p *Python) pages(addr uintptr) (allocation, error) {
	for a, fld := range p.fields {
		assert(a == fld.alloc.base)
		if addr == fld.alloc.base {
			pyc.Trace("found %v", fld.alloc)
			return fld.alloc, nil
		}
	}
	return allocation{}, fmt.Errorf("allocation 0x%x not found", addr)
}

func (p *Python) free(inferior *ptrace.Tracee, bp debug.Breakpoint) error {
	var stk x86_64

	// when we see a malloc, we break at the allocation site so that we can read
	// the pointer value returned. we don't need to read free's return value (it
	// has none, of course), but we need to reinsert the breakpoint that got us
	// here, and the site of the 'free' call is easy to lookup.
	raddr := uintptr(stk.RetAddrTop(inferior))
	if err := p.AddBP(inferior, raddr, p.freeret); err != nil {
		return fmt.Errorf("error inserting freeret bp@0x%x: %v", raddr, err)
	}

	freearg := uintptr(stk.Arg1(inferior)) // what they're freeing
	// if it's not page-aligned, this isn't our buffer.
	if freearg == 0x0 || freearg&0xfff > 0 {
		pyc.Trace("0x%x is not ours.", freearg)
		return nil
	}
	alc, err := p.pages(freearg) // figure out pages from address
	pyc.Trace("free(0x%x) [ours: %v]", freearg, err == nil)
	return nil
	if err != nil {
		// Not necessarily an error.  Could be memory we decided not to instrument.
		pyc.Trace("allocation 0x%x not found; not instrumented?", freearg)
		return nil
	}
	assert(alc.base == freearg)
	if err := p.DropWatch(inferior, alc); err != nil {
		pyc.Warn("We weren't watching %v... (%v)\n", alc, err)
		return err
	}
	p.destroy(alc.base)

	return nil
}

func (p *Python) freeret(inferior *ptrace.Tracee, bp debug.Breakpoint) error {
	pyc.Trace("re-adding 'free' (0x%x) bp", p.faddr)
	if err := p.AddBP(inferior, p.faddr, p.free); err != nil {
		return fmt.Errorf("error reinserting 'free' BP@0x%x: %v", p.faddr, err)
	}
	return nil
}

// adds an allocation to our list of 'we need to re-enable access detection on
// this'.
func (p *Python) add_blocker(alc *allocation) {
	if p.todeny == nil {
		p.todeny = make(map[uintptr]*allocation)
	}
	assert(p.todeny[alc.base] == nil) // i.e. not there already.
	p.todeny[alc.base] = alc
}

func (p *Python) access(inferior *ptrace.Tracee, pages allocation) error {
	pyc.Trace("inferior accessed %v at 0x%x", pages, whereis(inferior))
	// get rid of the segv, so execution will correctly continue when we're done.
	if err := inferior.ClearSignal(); err != nil {
		return err
	}

	// 'accessret' needs this to know *which* access it is reinstating.
	fld := p.fields[pages.base]
	p.add_blocker(&fld.alloc)

	// Okay, BPs are set for the loop header.  Now also figure out where we're
	// returning to, so we can set a BP there && enable access detection again.
	var stk x86_64
	// By my reasoning, we are in the middle of a function (we just came back
	// from a call!).. but experience and testing shows that the stack is almost
	// always setup such that we are in a prologue/epilogue...
	raddr := stk.RetAddrTop(inferior)
	pyc.Trace("want to add re-enable protection @ 0x%x", raddr)
	err := p.AddBP(inferior, raddr, p.accessret)
	if err != nil && err != debug.ErrAlreadyBroken {
		// okay... try again assuming we are not in a prologue/epilogue.
		raddr = stk.RetAddrMid(inferior)
		pyc.Warn("bad return address (%v). will try @ 0x%x", err, raddr)
		err := p.AddBP(inferior, raddr, p.accessret)
		if err != nil && err != debug.ErrAlreadyBroken {
			// *still* no luck.  Okay, just search for a 'ret' insn, but from the top
			// of the function we are in now, not the current iptr
			pyc.Warn("That failed too (%v); searching for ret instead.", err)
			symbol, err := where(inferior)
			if err != nil {
				return fmt.Errorf("dunno where are: %v", err)
			}
			ret, err := find_opcode(x86asm.RET, inferior, symbol.Address())
			if err != nil {
				return fmt.Errorf("did not find RET in %v: %v", symbol, err)
			}
			if err := p.AddBP(inferior, ret, p.accessret); err != nil {
				return fmt.Errorf("all methods for finding a good breakpoint to "+
					"re-enable protection failed!  last one: %v\n", err)
			}
			pyc.Trace("(ret insn) set our BP (for DENY) at 0x%x", ret)
		}
	}

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
	pyc.Warn("building '%v' CFG", symbol)
	graph := memocfg(symbol)
	bb, err := basic_block(graph, whereis(inferior))
	if err != nil {
		return fmt.Errorf("Beware of grue: %v", err) // don't know where we are?
	}
	// Initialize our dims.
	fld.dims = make([]uint, 0)
	fld.state = stallow
	for _, hdr := range bb.Headers {
		pyc.Trace("inserting header BP @ 0x%x", hdr.Addr)
		if p.AddBP(inferior, hdr.Addr, p.header); err != nil {
			return fmt.Errorf("BP at loop header (0x%x): %v", hdr.Addr, err)
		}
	}
	p.fields[fld.alloc.base] = fld

	return nil
}

func (p *Python) header(inferior *ptrace.Tracee, bp debug.Breakpoint) error {
	pyc.Trace("header BP (%v) hit", bp)

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
	graph := memocfg(symbol)
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
	if err := debug.WaitUntil(inferior, cmpaddr); err != nil {
		return fmt.Errorf("executing in 'header' (sketch!): %v", err)
	}

	rf := rfaddr(insn_regs, cmpaddr)
	assert(rf != nil) // we just executed up until the CMP. now it's not there?

	values, err := readargs(ixn, rf, symbol.Name(), inferior)
	if err != nil {
		return err
	}
	larger := maxvalue(values)
	for j, fld := range p.fields {
		if fld.state == stallow {
			fld.state = sthdr
		}
		pyc.Trace("appending %d to %v", uint(larger), fld.dims)
		if fld.state == sthdr {
			fld.dims = append(fld.dims, uint(larger))
		}
		p.fields[j] = fld
	}

	// loop for any loop headers and set breakpoints there that will in turn call
	// us again: this is how we loop through the headers.
	for _, hdr := range bb.Headers {
		pyc.Trace("inserting header BP @ 0x%x", hdr.Addr)
		if p.AddBP(inferior, hdr.Addr, p.header); err != nil {
			return fmt.Errorf("BP at loop header (0x%x): %v", hdr.Addr, err)
		}
	}

	return nil
}

// Called when we're finished with some code that accessed our data of
// interest.  We need to re-enable memory protection here.  And maybe do some
// visualization, which is, ya know, our whole purpose here and all.
func (p *Python) accessret(inferior *ptrace.Tracee, bp debug.Breakpoint) error {
	if p.todeny == nil {
		pyc.Warn("Nothing to re-enable.  This means that the current function" +
			" free()d all memory that it accessed.  Unlikely but possible.")
		return nil
	}
	pyc.Trace("Re-enabling protection for %d allocs.", len(p.todeny))

	for _, alc := range p.todeny {
		_, err := p.pages(alc.base)
		if err != nil {
			pyc.Trace("allocation %v was removed, ignoring.", *alc)
			continue
		}
		assert(alc.base == p.fields[alc.base].alloc.base)

		if err := p.vis(inferior, alc.base); err != nil {
			return fmt.Errorf("could not vis %v: %v", alc, err)
		}

		pyc.Trace("Adding watch for %v", *alc)
		if err := p.AddWatch(inferior, *alc, p.access); err != nil {
			return err
		}
	}

	// now that we've processed our list, clear it.
	p.todeny = nil

	return nil
}

func (p *Python) Setup(inferior *ptrace.Tracee) error {
	if err := p.BaseEvent.Setup(inferior); err != nil {
		return err
	}

	p.fields = make(map[uintptr]field)
	p.todeny = make(map[uintptr]*allocation)

	tjfmalloc := symbol("__tjfmalloc", globals.symbols)
	assert(tjfmalloc != nil)
	p.tjfmalloc = tjfmalloc.Address()

	mloc := symbol("malloc", globals.symbols)
	assert(mloc != nil)
	p.maddr = mloc.Address()

	floc := symbol("free", globals.symbols)
	assert(floc != nil)
	p.faddr = floc.Address()

	assert(globals.program != "") // 'where' will not work, otherwise.

	// we get informed of which regions to care about at allocation sites.
	if err := p.AddBP(inferior, p.maddr, p.malloc); err != nil {
		return fmt.Errorf("could not add 'malloc' bp@0x%x: %v", p.maddr, err)
	}

	// free means we can/should stop watching that memory.
	if err := p.AddBP(inferior, p.faddr, p.free); err != nil {
		return fmt.Errorf("could not add initial 'free' bp@0x%x: %v", p.faddr, err)
	}

	if err := python.Initialize(); err != nil {
		return err
	}

	var err error
	p.module, err = python.Py_InitModule("simulation", []python.PyMethodDef{})
	if err != nil {
		return err
	}

	// Setup the default argv.  Apparently PyRun_SimpleFile etc. will not do this
	// for us, and then scripts will bail if they try to access sys.argv.  This
	// fixes it.
	argv := []string{"test.py"}
	python.PySys_SetArgv(argv)

	p.dict = python.PyModule_GetDict(p.module)
	if p.dict == nil {
		return errors.New("newly-created module has no dict?")
	}

	if i := python.PyRun_SimpleString("import simulation"); i != 0 {
		return errors.New("could not import module we created")
	}
	if i := python.PyRun_SimpleString("import numpy"); i != 0 {
		return errors.New("could not import numpy.")
	}

	gonpy.Import()

	pyc.Trace("Initialized.\n")

	return nil
}

func (p *Python) Close(inferior *ptrace.Tracee) error {
	if err := p.BaseEvent.Close(inferior); err != nil {
		return err
	}

	python.PyDict_Clear(p.dict)
	p.dict.Clear()
	p.module.Clear()
	p.dict = nil
	p.module = nil

	for _, fld := range p.fields {
		p.destroy(fld.alloc.base)
	}
	p.fields = nil

	if err := python.Finalize(); err != nil {
		return err
	}

	pyc.Trace("Finalized.\n")
	return nil
}
