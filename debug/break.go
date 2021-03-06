/* Distributed under the MIT license.  See the LICENSE file.
 * Copyright (c) 2014--2016 Thomas Fogal */
package debug

import "errors"
import "fmt"
import "io"
import "syscall"
import "github.com/tfogal/ptrace"

type Breakpoint struct {
	Address uintptr // where it was inserted
	insn    uint64  // the instruction before we clobbered it with a BP
}

func (b Breakpoint) String() string {
	return fmt.Sprintf("0x%x 0x%x", b.Address, b.insn)
}

// mask to apply to instructions when replacing their lead byte with 0xCC.
const imask = 0xffffffffffffff00

// Inserts a breakpoint at the given address.  You'll need the return value to
// remove the breakpoint.
func Break(inferior *ptrace.Tracee, address uintptr) (Breakpoint, error) {
	bp := Breakpoint{Address: address, insn: 0x0}

	var err error
	// a breakpoint is just 0xcc at the given address.  But we can only
	// read/write from the process in units of a word, so we mask it.
	bp.insn, err = inferior.ReadWord(address)
	if err != nil {
		return Breakpoint{}, fmt.Errorf("reading 0x%0x: %v", address, err)
	}

	// make sure we don't double-enable a BP.  That makes little sense.  Plus,
	// then we would need to unwrap/Unbreak them in the same order, which would
	// be hard to guarantee.  Better to just call it an error.
	if (bp.insn & (^uint64(imask))) == 0xcc {
		return Breakpoint{}, ErrAlreadyBroken
	}

	bpinsn := (bp.insn & imask) | 0xcc // 0xcc is "the" breakpoint opcode.

	// overwrite with breakpoint (0xcc)
	err = inferior.WriteWord(address, bpinsn)
	if err != nil {
		return Breakpoint{}, fmt.Errorf("replacing 0x%0x: %v", address, err)
	}

	return bp, nil
}

// Removes the given breakpoint.
func Unbreak(inferior *ptrace.Tracee, bp Breakpoint) error {
	if bp.Address == 0x0 {
		return errors.New("invalid 0x0 address!")
	}
	// restore the correct instruction ...
	insn, err := inferior.ReadWord(bp.Address)
	if err != nil {
		return err
	}

	// Make sure the breakpoint actually matches what's there now.  This might
	// not be true in general, to be honest: self-modifying code breaks this.
	if ((bp.insn & imask) | 0xcc) != insn {
		return fmt.Errorf("instruction doesn't match. memory changed or SMC?")
	}

	err = inferior.WriteWord(bp.Address, (insn&imask)|(bp.insn&0xFF))
	if err != nil {
		return fmt.Errorf("could not restore insn: %v", err)
	}

	return nil
}

// Move the instruction pointer back one.  Needed after we hit a breakpoint,
// otherwise we'd essentially be jumping into the middle of an instruction!
func Stepback(inferior *ptrace.Tracee) error {
	iptr, err := inferior.GetIPtr()
	if err != nil {
		return fmt.Errorf("could not get insn ptr: %v", err)
	}
	err = inferior.SetIPtr(iptr - 1)
	if err != nil {
		return fmt.Errorf("could not set insn pointer: %v", err)
	}

	return nil
}

var (
	ErrSegFault      = errors.New("SIGSEGV")
	ErrAlreadyBroken = errors.New("Breakpoint is already there")
)

func WaitUntil(inferior *ptrace.Tracee, address uintptr) error {
	bp, err := Break(inferior, address)
	if err != nil {
		return fmt.Errorf("could not set bp: %v", err)
	}

	// wait for the tracee to hit that BP.
	if err = inferior.Continue(); err != nil {
		return fmt.Errorf("child could not continue: %v", err)
	}
	stat := <-inferior.Events()
	status := stat.(syscall.WaitStatus)

	// if it exited, we can't unset the breakpoint or do anything, really; just
	// bail now.
	if status.Exited() || status.StopSignal() == syscall.SIGCHLD {
		return io.EOF
	}

	// remove the breakpoint to leave our inferior in a consistent state, even if
	// it just had something crazy happen (i.e. crashing, signal, etc.)
	err = Unbreak(inferior, bp)
	if err != nil {
		return fmt.Errorf("could not unset bp: %v", err)
	}

	// maybe it didn't get hit at all?  program could have ended.
	switch {
	case status.CoreDump():
		return errors.New("abnormal termination, core dumped")
	case status.StopSignal() == syscall.SIGSEGV:
		// A segfault might be expected: we could have caused it with our
		// malloc-rewrite-mprotect scheme.
		return ErrSegFault
	case status.StopSignal() != syscall.SIGTRAP:
		addr, err := inferior.GetIPtr()
		if err != nil {
			return fmt.Errorf("unexpected signal %d and could not get addr!",
				status.StopSignal())
		}
		return fmt.Errorf("unexpected signal %d @ 0x%0x", status.StopSignal(), addr)
	}

	// back up the instruction pointer so the break'd insn will now execute.
	if err := Stepback(inferior); err != nil {
		return fmt.Errorf("error backing up insn ptr: %v", err)
	}

	iptr, err := inferior.GetIPtr()
	if err != nil {
		return err
	}
	if iptr != address {
		panic("stopped somewhere else; maybe we hit a different breakpoint?")
	}

	return nil
}
