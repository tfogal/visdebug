package debug;

import(
  "errors"
  "os"
  "runtime"
  "syscall"
)

var(
  chld *os.Process
)

func StartUnderOurPurview(program string, arguments []string) (*os.Process, error) {
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

  runtime.LockOSThread(); // needed to make Ptrace'd processes work.
  var err error;
  chld, err = os.StartProcess(program, arguments, &attr);
  if err != nil { return nil, err; }

  err = syscall.PtraceSetOptions(chld.Pid, syscall.PTRACE_O_TRACEEXEC)
  return chld, err
/*
  chld := Fork();
  if(chld == 0) {
    ptrace.TraceMe();
    errs := Exec(program, arguments, nil)
    panic(errs);
  }
  var wstat syscall.WaitStatus;
  opt := 0
  _, err := syscall.Wait4(chld, &wstat, opt, nil);
  if err != nil {
    // kill the child so we can have the semantics of not creating resources on
    // error.
    syscall.Kill(chld, syscall.SIGKILL);
    return chld, err;
  }
  return chld, nil;
*/
}

func Watch(addr *uint8) (error) {
  return errors.New("unimplemented");
}

func breakpoint(addr *uint8) (error) {
  return errors.New("unimplemented");
}
