package bfd
import "fmt"
import "io"
import "os"
import "syscall"
import "testing"
import "github.com/tfogal/ptrace"

func TestReadSymbols(t *testing.T) {
  descriptor, err := OpenR("../testprograms/dimensional", "")
  if err != nil {
    t.Fatalf("error opening bfd: %v\n", err)
  }
  symbols := Symbols(descriptor)

  if err := Close(descriptor) ; err != nil {
    t.Fatalf("could not close bfd file: %v\n", err)
  }
  if len(symbols) < 20 {
    t.Fatalf("symbol reading broken?  only read %d symbols.", len(symbols))
  }
}

func startproc(arguments []string, t *testing.T) (*os.Process, error) {
  sattr := syscall.SysProcAttr{
    Chroot: "",
    Credential: nil,
    Ptrace: true,
    Setsid: false,
    Setpgid: false,
    Setctty: false,
    Noctty: false,
    Ctty: 0,
    Pdeathsig: syscall.SIGCHLD,
  };
  files := []*os.File{os.Stdin, os.Stdout, os.Stderr};
  attr := os.ProcAttr{ Dir: ".", Env: nil, Files: files, Sys: &sattr };

  chld, err := os.StartProcess(arguments[0], arguments, &attr);
  if err != nil { return nil, err }

  if err = syscall.Kill(chld.Pid, syscall.SIGSTOP) ; err != nil {
    t.Fatalf("could not stop child %d! %d\n", chld.Pid)
  }
  return chld, err
}

// Write a '1' into /tmp/.garbage and then close it.
// Pause execution until /tmp/.garbage reads '0'.
func badsync() {
  const SYNCFILE string = "/tmp/.garbage";
  fmt.Printf("[Go] Writing 1 into %s\n", SYNCFILE)
  fp, err := os.OpenFile(SYNCFILE, os.O_RDWR | os.O_CREATE | os.O_TRUNC, 0666)
  if err != nil { panic(err) }
  _, err = fmt.Fprintf(fp, "%d\n", 1)
  if err != nil { panic(err) }
  fp.Close()

  v := uint(42)
  fmt.Printf("[Go] Waiting for 0 in %s...\n", SYNCFILE)
  for v != 0 {
    fp, err = os.Open(SYNCFILE)
    if err != nil { fp.Close(); panic(err) }
    v = 42
    _, err = fmt.Fscanf(fp, "%d", &v)
    if err != nil && err != io.EOF { fp.Close(); panic(err) }
    fp.Close()
  }
  if err = os.Remove(SYNCFILE) ; err != nil {
    fmt.Fprintf(os.Stderr, "[Go] error removing %s! %v\n", SYNCFILE, err)
  }
}

func TestSymbolsProcess(t *testing.T) {
  argv := []string{"../testprograms/pauser", "3"}
  inferior, err := ptrace.Exec(argv[0], argv)
  if err != nil {
    t.Fatalf("could not start subprocess, bailing: %v", err)
    t.FailNow()
  }
  t.Logf("inferior started with PID %d\n", inferior.PID())
  /* wait for 1 event, i.e. the notification that the child has exec'd */
  status := <- inferior.Events()
  if status == nil {
    t.Fatalf("no events?")
    inferior.Close()
    return
  }
  /* let the child run so we can do our synchronization stuff. */
  inferior.Continue()
  badsync()
  /* stop the child now that we're synchronized: we can't read from it if it's
   * actively running. */
  if err = inferior.SendSignal(syscall.SIGSTOP) ; err != nil {
    t.Fatalf("error telling child to stop: %v", err)
  }

  SymbolsProcess(inferior)
  inferior.SendSignal(syscall.SIGKILL)
}

// This of course doesn't work unless you're running the executable out of
// band.  Edit the PID to get it working.  Or code up a fork/exec here
// explicitly and attach to it after.
func TestAttach(t *testing.T) {
  inferior, err := ptrace.Attach(10709)
  if err != nil {
    t.Skipf("could not attach (%v), can't run test.", err)
  }
  t.Logf("inferior PID %d attached.\n", inferior.PID())
  /* wait for 1 event, i.e. the notification that the child has exec'd */
  status := <- inferior.Events()
  if status == nil {
    t.Fatalf("no events?")
    inferior.Close()
    return
  }

  SymbolsProcess(inferior)
}

func symbol(symname string, symbols []Symbol) *Symbol {
  for _, sym := range symbols {
    if sym.Name() == symname {
      return &sym
    }
  }
  return nil
}
func present(symname string, symbols []Symbol) bool {
  return symbol(symname, symbols) != nil
}
func assert(conditional bool) {
  if !conditional { panic("failed conditional") }
}

func procstate(pid int, stat syscall.WaitStatus) {
  if stat.Continued() { fmt.Printf("process %d continued\n", pid) }
  if stat.CoreDump() { fmt.Printf("process %d produced core dump!\n", pid) }
  if stat.Exited() {
    fmt.Printf("process %d exited with status %d\n", pid, stat.ExitStatus())
  }
  if stat.Signaled() {
    fmt.Printf("process %d was signaled by signal %d\n", pid, stat.Signal())
  }
  if stat.Stopped() {
    fmt.Printf("process %d was stopped by signal %d\n", pid, stat.StopSignal())
  }
  if stat.TrapCause() != 0 {
    fmt.Printf("process %d's trap cause was %d\n", pid, stat.TrapCause())
  }
}

func TestMallocInterrupt(t *testing.T) {
  argv := []string{"../testprograms/pauser", "3"}
  inferior, err := ptrace.Exec(argv[0], argv)
  if err != nil {
    t.Fatalf("could not start subprocess, bailing: %v", err)
    t.FailNow()
  }
  t.Logf("inferior started with PID %d\n", inferior.PID())
  /* wait for 1 event, i.e. the notification that the child has exec'd */
  status := <- inferior.Events()
  if status == nil {
    t.Fatalf("no events?")
    inferior.Close()
    return
  }
  // let the child run so the loader can run through all its stuff.  our
  // 'badsync' won't return until the child gets into its own badsync, which is
  // of course in its main, and thus guarantees the loader is finished.
  inferior.Continue()
  badsync()
  // now stop the child; can't read from a running process.
  if err = inferior.SendSignal(syscall.SIGSTOP) ; err != nil {
    t.Fatalf("error telling child to stop: %v", err)
  }
  // since the tracer is notified of all inferior signals, we'll get a
  // notification of the SIGSTOP we just sent.  Clean off the event queue.
  status = <- inferior.Events()
  ws := status.(syscall.WaitStatus)
  // .. and make sure it was the event we expected.
  if !ws.Stopped() || ws.StopSignal() != 19 {
    t.Fatalf("should have received stopping notification?")
  }

  symbols, err := SymbolsProcess(inferior)
  if err != nil { t.Fatalf("%v", err) }

  // now insert our breakpoint and tell it to move on.
  assert(present("malloc", symbols))
  symmalloc := symbol("malloc", symbols)

  // get the instruction that's at that address first, so we can restore later.
  minsn, err := inferior.ReadWord(symmalloc.Address())
  if err != nil { t.Fatalf("%v", err) }
  if minsn != 0xec834853fd894855 {
    t.Fatalf("malloc call shellcode is unexpected: 0x%x\n", minsn)
  }
  bp := (minsn & 0xffffffffffffff00) | 0xcc

  // overwrite with breakpoint (0xcc)
  err = inferior.WriteWord(symmalloc.Address(), bp)
  if err != nil { t.Fatalf("%v\n", err) }

  // let the child continue.
  inferior.Continue()

  // now wait for the child to hit the breakpoint
  status = <- inferior.Events()
  ws = status.(syscall.WaitStatus)
  if !ws.Stopped() || ws.StopSignal() != 5 {
    t.Fatalf("we expected to hit a breakpoint, but did not.")
  }
  fmt.Printf("hit the breakpoint! good.\n")

  // restore the instruction.
  err = inferior.WriteWord(symmalloc.Address(), minsn)
  if err != nil { t.Fatalf("could not restore insn: %v\n", err) }

  // the CPU now *passed* that instruction, so we need to knock the
  // instruction pointer back a notch for it to run properly.
  iptr, err := inferior.GetIPtr()
  if err != nil { t.Fatalf("could not get insn ptr: %v\n", err) }

  // ... actually, this should be minus the size of the last instruction!
  err = inferior.SetIPtr(iptr - 1)
  if err != nil { t.Fatalf("could not set insn pointer: %v\n", err) }

  err = inferior.Continue()
  if err != nil { t.Fatalf("continuing failed: %v\n", err) }

  status = <- inferior.Events()
  procstate(inferior.PID(), status.(syscall.WaitStatus))
}
