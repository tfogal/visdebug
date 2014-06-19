package bfd

import "os"
import "syscall"
import "testing"

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

func TestSymbolsProcess(t *testing.T) {
  inferior, err := startproc([]string{"../testprograms/pauser", "3"}, t)
  if err != nil {
    t.Fatalf("could not start subprocess, bailing.")
    t.FailNow()
  }
  SymbolsProcess(inferior.Pid);
}
