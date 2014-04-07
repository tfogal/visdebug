package main;

import(
  "./bfd"
  "./debug"
  "fmt"
  "syscall"
)

func procstatus(pid int, stat syscall.WaitStatus) {
  if stat.CoreDump() { panic("core dumped"); }
  if stat.Continued() { fmt.Printf("continued\n"); }
  if stat.Exited() {
    fmt.Printf("exited with status: %d\n", stat.ExitStatus())
  }
  if stat.Signaled() {
    fmt.Printf("received signal: %v\n", stat.Signal())
    panic("unexpected signal")
  }
  if stat.Stopped() {
    fmt.Printf("stopped with signal: %v\n", stat.StopSignal())
  }
  fmt.Printf("PID %d trap cause: %d\n", pid, stat.TrapCause())
}

func readsymbols(filename string) {
  desc, err := bfd.OpenR(filename, "");
  if err != nil {
    fmt.Printf("error opening bfd: %v\n", err);
    panic("bfd.OpenR");
  }
  bfd.Symbols(desc);
  if err = bfd.Close(desc) ; err != nil {
    fmt.Printf("error closing bfd: %v\n", err);
    panic("bfd.Close")
  }
}

func main() {
  //program := []string{"/bin/true"};
  program := []string{"/tmp/a.out"};
  readsymbols(program[0]);

  proc, err := debug.StartUnderOurPurview(program[0], program)
  if err != nil {
    fmt.Printf("could not start program: %v\n", err)
    panic("failed starting proc")
  }

  var insns uint64
  insns = 0

  var wstat syscall.WaitStatus
  _, err = syscall.Wait4(proc.Pid, &wstat, 0, nil)
  if err != nil {
    fmt.Printf("wait4 error: %v\n", err)
    panic("wait")
  }

  for wstat.Stopped() {
    insns++;
    if wstat.Exited() { break }
    var regs syscall.PtraceRegs
    err = syscall.PtraceGetRegs(proc.Pid, &regs)
    if err != nil {
      fmt.Printf("get regs error: %v\n", err);
      break;
    }
    err = syscall.PtraceSingleStep(proc.Pid);
    if err != nil {
      panic("single step")
    }
    _, err = syscall.Wait4(proc.Pid, &wstat, 0, nil)
    if err != nil {
      fmt.Printf("wait4 error: %v\n", err)
      panic("wait")
    }
  }
  fmt.Printf("%d instructions\n", insns)
}
