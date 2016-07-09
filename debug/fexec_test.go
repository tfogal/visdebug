package debug

import "os"
import "syscall"
import "testing"

func testExecLs(t *testing.T) {
	t.Logf("execls test..")
	pid := Fork()
	if pid == 0 {
		wrap_exec("/bin/true", []string{"/bin/true"}, nil)
		//    Exec("/bin/ls", []string{"/bin/ls"}, nil);
		/* if we got here, something went wrong. */
		mypid := os.Getpid()
		syscall.Kill(mypid, syscall.SIGKILL)
		/* okay, if *that* failed too.. at least exit so our test system doesn't
		 * leave zombies. */
		os.Exit(86)
	} else {
		var wstat syscall.WaitStatus
		syscall.Wait4(pid, &wstat, 0, nil)
		if wstat.Signaled() {
			t.Fatalf("child exited via signal")
		}
		if !wstat.Exited() {
			t.Fatalf("child did not exit cleanly")
		}
	}
}

func testExecBadPath(t *testing.T) {
	t.Logf("exec bad path test..")
	pid := Fork()
	if pid == 0 {
		Exec("/nonexistent", []string{"/nonexistent"}, nil)
		// we expect that not to work, so we should get here and run this:
		os.Exit(42)
	} else {
		var wstat syscall.WaitStatus
		syscall.Wait4(pid, &wstat, 0, nil)
		if wstat.ExitStatus() != 42 {
			t.Fatalf("Exec did not fail correctly (%d)", wstat.ExitStatus())
		}
	}
}

func testExecEnv(t *testing.T) {
	t.Logf("exec env test..\n")
	pid := Fork()
	if pid == 0 {
		wrap_exec("/bin/true", []string{"/bin/true"},
			[]string{"HOME=/tmp", "PATH=/bin:/usr/bin"})
		os.Exit(42)
	} else {
		var wstat syscall.WaitStatus
		syscall.Wait4(pid, &wstat, 0, nil)
		if !wstat.Exited() {
			t.Fatalf("fork-exec of ls did not finish")
		}
		if wstat.ExitStatus() != 0 {
			t.Fatalf("Exec did not exit correctly (%d)", wstat.ExitStatus())
		}
	}
}

func wrap_exec(program string, argv []string, envp []string) error {
	os.Stdin.Close()
	os.Stdout.Close()
	os.Stderr.Close()
	return Exec(program, argv, envp)
}
