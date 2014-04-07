package debug
import "syscall"
import "testing"

func TestStartControlledBasic(t *testing.T) {
  argv := []string{"/bin/true"}
  proc, err := StartUnderOurPurview(argv[0], argv)
  if err != nil {
    t.Fatalf("could not create process: %v", err)
    t.FailNow();
  }
  err = syscall.PtraceCont(proc.Pid, 0)
  if err != nil {
    t.Fatalf("continuing failed: %v\n", err)
    t.FailNow(); // otherwise we'd deadlock.
  }
  state, err := proc.Wait()
  if err != nil {
    t.Fatalf("waiting failed\n", err)
    t.FailNow();
  }
  if !state.Success() {
    t.Fatalf("process was unsuccessful: %v\n", state);
  }
  if !state.Exited() {
    t.Fatalf("process did not exit!\n");
  }
  if state.Exited() { return; }
}
