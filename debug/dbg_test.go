package debug
import "os"
import "os/signal"
import "syscall"
import "testing"

func TestStartControlledBasic(t *testing.T) {
  argv := []string{"/bin/true"}
  proc, err := StartUnderOurPurview(argv[0], argv)
  if err != nil {
    t.Fatalf("could not create process")
  }
  _, err = proc.Wait()
  if err != nil {
    t.Fatalf("waiting failed")
  }
}

// make sure the process is traced.
func TestStartControlledTraced(t *testing.T) {
  argv := []string{"/bin/true"}
  proc, err := StartUnderOurPurview(argv[0], argv)
  if err != nil {
    t.Fatalf("could not create process")
  }
  sigchan := make(chan os.Signal, 1)
  signal.Notify(sigchan, syscall.SIGSTOP)
  _ = <-sigchan
  t.Logf("received SIGSTOP");
  _, err = proc.Wait()
  if err != nil {
    t.Fatalf("waiting failed")
  }
}
