package main

import (
	"./debug"
	"errors"
	"fmt"
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

	// figure out where the caller is and set a BP there.
	retaddr := stk.RetAddr(inferior)

	if err := mt.AddBP(inferior, retaddr, mt.mallocret); err != nil {
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

	mloc := symbol("malloc", globals.symbols)
	assert(mloc != nil)

	// re-insert our BP for malloc.
	if err := mt.AddBP(inferior, mloc.Address(), mt.malloc); err != nil {
		return err
	}
	return nil
}

func (mt *MallocTrace) free(inferior *ptrace.Tracee,
	bp debug.Breakpoint) error {
	var stk x86_64
	// make sure this BP gets re-added when we come back.
	// I do not understand why this needs the 'Top' variant, but it does...
	raddr := uintptr(stk.RetAddrTop(inferior))
	if err := mt.AddBP(inferior, raddr, mt.freeret); err != nil {
		return err
	}

	// get the thing that is being freed.
	ptr := uintptr(stk.Arg1(inferior))
	fmt.Printf("free(0x%x)\n", ptr)

	return nil
}

func (mt *MallocTrace) freeret(inferior *ptrace.Tracee,
	bp debug.Breakpoint) error {
	free := symbol("free", globals.symbols)
	if err := mt.AddBP(inferior, free.Address(), mt.free); err != nil {
		return err
	}

	return nil
}

func (mt *MallocTrace) Setup(inferior *ptrace.Tracee) error {
	if err := mt.BaseEvent.Setup(inferior); err != nil {
		return err
	}

	symmalloc := symbol("malloc", globals.symbols)
	if symmalloc == nil {
		return errors.New("'malloc' not available; error reading symtab?")
	}
	symfree := symbol("free", globals.symbols)

	if err := mt.AddBP(inferior, symmalloc.Address(), mt.malloc); err != nil {
		return err
	}
	if err := mt.AddBP(inferior, symfree.Address(), mt.free); err != nil {
		return err
	}
	return nil
}

func (mt *MallocTrace) Close(*ptrace.Tracee) error {
	return nil
}
