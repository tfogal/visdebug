package debug

import "errors"
import "fmt"
import "io"
import "syscall"
import "github.com/tfogal/ptrace"

type Breakpoint struct {
  address uintptr // where it was inserted
  insn uint64 // the instruction before we clobbered it with a BP
}

// mask to apply to instructions when replacing their lead byte with 0xCC.
const imask = 0xffffffffffffff00

// Inserts a breakpoint at the given address.  You'll need the return value to
// remove the breakpoint.
func Break(inferior *ptrace.Tracee, address uintptr) (Breakpoint, error) {
  bp := Breakpoint{address: address, insn: 0x0}

  var err error
  // a breakpoint is just 0xcc at the given address.  But we can only
  // read/write from the process in units of a word, so we mask it.
  bp.insn, err = inferior.ReadWord(address)
  if err != nil { return Breakpoint{}, err }

  bpinsn := (bp.insn & imask) | 0xcc // 0xcc is "the" breakpoint opcode.

  // overwrite with breakpoint (0xcc)
  err = inferior.WriteWord(address, bpinsn)
  if err != nil { return Breakpoint{}, err }

  return bp, nil
}

// Removes the given breakpoint.
func Unbreak(inferior *ptrace.Tracee, bp Breakpoint) error {
  // restore the correct instruction ...
  insn, err := inferior.ReadWord(bp.address)
  if err != nil { return err }

  // Make sure the breakpoint actually matches what's there now.  This might
  // not be true in general, to be honest: self-modifying code breaks this.
  if ((bp.insn & imask) | 0xcc) != insn {
    return fmt.Errorf("instruction doesn't match. memory changed or SMC?")
  }

  err = inferior.WriteWord(bp.address, (insn & imask) | (bp.insn & 0xFF))
  if err != nil { return fmt.Errorf("could not restore insn: %v\n", err) }

  return nil
}

// Move the instruction pointer back one.  Needed after we hit a breakpoint,
// otherwise we'd essentially be jumping into the middle of an instruction!
func Stepback(inferior *ptrace.Tracee) error {
  iptr, err := inferior.GetIPtr()
  if err != nil { return fmt.Errorf("could not get insn ptr: %v\n", err) }
  err = inferior.SetIPtr(iptr - 1)
  if err != nil { return fmt.Errorf("could not set insn pointer: %v\n", err) }

  return nil
}

func WaitUntil(inferior *ptrace.Tracee, address uintptr) error {
  bp, err := Break(inferior, address)
  if err != nil { return err }

  // wait for the tracee to hit that BP.
  if err = inferior.Continue() ; err != nil {
    return fmt.Errorf("child could not continue: %v", err)
  }
  stat := <- inferior.Events()
  status := stat.(syscall.WaitStatus)
  // maybe it didn't get hit at all?  program could have ended.
  if status.Exited() || status.StopSignal() == syscall.SIGCHLD { return io.EOF
}
  if status.CoreDump() {
    return errors.New("abnormal termination, core dumped")
  }
  if status.StopSignal() != syscall.SIGTRAP {
    return fmt.Errorf("unexpected signal %d", status.StopSignal())
  }

  err = Unbreak(inferior, bp)
  if err != nil { return err }

  // back up the instruction pointer so the break'd call will now execute.
  if err := Stepback(inferior) ; err != nil {
    return err
  }

  return nil
}
