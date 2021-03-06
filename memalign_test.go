/* Distributed under the MIT license.  See the LICENSE file.
 * Copyright (c) 2014--2016 Thomas Fogal */
package main

import "syscall"
import "testing"
import "./bfd"
import "./debug"
import "github.com/tfogal/ptrace"

func startup(argv []string) (*ptrace.Tracee, error) {
	inferior, err := ptrace.Exec(argv[0], argv)
	if err != nil {
		return nil, err
	}
	<-inferior.Events() // eat 'process is starting' event.

	if err := MainSync(argv[0], inferior); err != nil {
		inferior.Close()
		return nil, err
	}
	return inferior, nil
}

func TestAllocInferior(t *testing.T) {
	argv := []string{"testprograms/dimensional", "3"}
	inferior, err := startup(argv)
	if err != nil {
		t.Fatalf("can't exec child: %v", err)
	}
	defer inferior.Close()

	symbols, err := bfd.SymbolsProcess(inferior)
	if err != nil {
		t.Fatalf("could not read smbols: %v\n", err)
	}

	addr, err := setup_tjfmalloc(inferior)
	if err != nil {
		t.Fatalf("error inserting our malloc: %v", err)
	}

	if addr < symbol("main", symbols).Address() {
		t.Fatalf("address 0x%0x makes no sense", addr)
	}

	if err := inferior.Continue(); err != nil {
		t.Fatalf("could not finish program: %v", err)
	}
	stat := <-inferior.Events() // let it finish.
	status := stat.(syscall.WaitStatus)
	if status.Exited() {
		return
	}
	if status.StopSignal() == syscall.SIGSEGV {
		iptr, err := inferior.GetIPtr()
		if err != nil {
			t.Fatalf("program segfaulted, and inferior is invalid.")
		}
		t.Fatalf("program segfaulted at 0x%x after resume.", iptr)
	}
}

func TestExecFill(t *testing.T) {
	argv := []string{"testprograms/dimensional", "3"}
	inferior, err := startup(argv)
	if err != nil {
		t.Fatalf("startup failed: %v", err)
	}
	defer inferior.Close()

	symbols, err := bfd.SymbolsProcess(inferior)
	if err != nil {
		t.Fatalf("could not read smbols: %v\n", err)
	}

	addr, err := setup_tjfmalloc(inferior)
	if err != nil {
		t.Fatalf("error inserting our malloc: %v", err)
	}

	calloc := symbol("calloc", symbols)
	if calloc == nil || calloc.Address() == 0x0 {
		t.Fatalf("calloc symbol not available, symbtab broken?")
	}
	if err := debug.WaitUntil(inferior, calloc.Address()); err != nil {
		t.Fatalf("never hit a calloc? %v", err)
	}

	var stack x86_64
	// save the return address so we know where to go back to.
	retsite := stack.RetAddr(inferior)
	nbytes := stack.Arg1(inferior)

	tst.Trace("mallocing %v bytes but jumping to 0x%0x instead. Ret to: 0x%0x\n",
		nbytes, addr, retsite)
	// now, instead, "jump" to our 'new' function.
	if err := inferior.SetIPtr(addr); err != nil {
		t.Fatalf("jumping to our in-mem function: %v", err)
	}
	// let our replacement malloc run
	if err := debug.WaitUntil(inferior, retsite); err != nil {
		t.Fatalf("never came back from our function? %v", err)
	}
	rval := stack.RetVal(inferior)
	if rval == 0x0 {
		t.Fatalf("retval should not be null!")
	}

	// insns_stdout(inferior)
	if err := inferior.Continue(); err != nil {
		t.Fatalf("could not continue: %v", err)
	}
	<-inferior.Events() // let it go.
}

func TestAllowDeny(t *testing.T) {
	argv := []string{"testprograms/dimensional", "3"}
	inferior, err := startup(argv)
	if err != nil {
		t.Fatalf("startup failed: %v", err)
	}
	defer inferior.Close()

	iptr, err := inferior.GetIPtr()
	if err != nil {
		t.Fatalf("could not get current insn ptr: %v\n", err)
	}
	tst.Trace("retsite will be: 0x%0x\n", iptr)
	alc := allocation{base: 0x401000, length: 4096}
	err = allow(inferior, alc.base, alc.length, iptr)
	if err != nil {
		t.Fatalf("allow1: %v\n", err)
	}
	err = deny(inferior, alc.base, alc.length, iptr)
	if err != nil {
		t.Fatalf("allow1: %v\n", err)
	}
	err = iprotect(inferior, alc.base, alc.length, prot_EXEC, iptr)
	if err != nil {
		t.Fatalf("allow1: %v\n", err)
	}

	if err := inferior.Continue(); err != nil {
		t.Fatalf("continued exec: %v\n", err)
	}

	stat := <-inferior.Events()
	status := stat.(syscall.WaitStatus)
	if !status.Exited() {
		t.Fatalf("bad exit: %v\n", status)
	}
}
