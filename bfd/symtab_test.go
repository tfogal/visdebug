package bfd
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
  stat := status.(syscall.WaitStatus)
  if stat.Exited() { t.Log("exited") }
  if stat.Stopped() { t.Log("stopped") }

  SymbolsProcess(inferior)
  inferior.SendSignal(syscall.SIGKILL)
}
