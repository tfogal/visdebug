/* Distributed under the MIT license.  See the LICENSE file.
 * Copyright (c) 2014--2016 Thomas Fogal */
package bfd

import "fmt"
import "sort"
import "syscall"
import "testing"
import "github.com/tfogal/ptrace"
import "../debug"

func TestReadSymbols(t *testing.T) {
	symbols, err := Symbols("../testprograms/dimensional")
	if err != nil {
		t.Fatalf("error loading symbols: %v\n", err)
	}

	if len(symbols) < 20 {
		t.Fatalf("symbol reading broken?  only read %d symbols.", len(symbols))
	}
}

func TestSymbolsProcess(t *testing.T) {
	argv := []string{"../testprograms/dimensional", "3"}
	inferior, err := ptrace.Exec(argv[0], argv)
	if err != nil {
		t.Fatalf("could not start subprocess, bailing: %v", err)
		t.FailNow()
	}
	defer inferior.Close()

	// wait for 1 event, i.e. the notification that the child has exec'd
	status := <-inferior.Events()
	if status == nil {
		t.Fatalf("no events?")
	}
	// wait until main so that the dynamic loader can run.
	assert(addr_main(argv[0]) != 0x0)
	debug.WaitUntil(inferior, addr_main(argv[0]))

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
	defer inferior.Close()
	t.Logf("inferior PID %d attached.\n", inferior.PID())
	/* wait for 1 event, i.e. the notification of the attach */
	status := <-inferior.Events()
	if status == nil {
		t.Fatalf("no events?")
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
	if !conditional {
		panic("failed conditional")
	}
}

func procstate(pid int, stat syscall.WaitStatus) {
	if stat.Continued() {
		fmt.Printf("process %d continued\n", pid)
	}
	if stat.CoreDump() {
		fmt.Printf("process %d produced core dump!\n", pid)
	}
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

func addr_main(program string) uintptr {
	symbols, err := Symbols(program)
	if err != nil {
		panic(err)
	}

	symmain := symbol("main", symbols)
	return symmain.Address()
}

func TestMallocInterrupt(t *testing.T) {
	argv := []string{"../testprograms/dimensional", "3"}
	inferior, err := ptrace.Exec(argv[0], argv)
	if err != nil {
		t.Fatalf("could not start subprocess, bailing: %v", err)
	}
	defer inferior.Close()
	// wait for 1 event, i.e. the notification that the child has exec'd
	status := <-inferior.Events()
	if status == nil {
		t.Fatalf("no events?")
	}

	// pause the process until we get to 'main'.  This lets the process run
	// through the dynamic loader, so that we can grab functions in e.g. libc.
	if addr_main(argv[0]) == 0x0 {
		t.Fatalf("could not get main's address")
	}
	err = debug.WaitUntil(inferior, addr_main(argv[0]))
	if err != nil {
		t.Fatalf("could not wait until main: %v\n", err)
	}

	symbols, err := SymbolsProcess(inferior)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// now insert our breakpoint and tell it to move on.
	assert(present("calloc", symbols))
	symcalloc := symbol("calloc", symbols)

	bp, err := debug.Break(inferior, symcalloc.Address())
	if err != nil {
		t.Fatalf("insert breakpoint: %v\n", err)
	}

	// let the child run until 'malloc'.
	if err := inferior.Continue(); err != nil {
		t.Fatalf("cont: %v\n", err)
	}
	status = <-inferior.Events() // actual wait comes here.
	ws := status.(syscall.WaitStatus)
	if !ws.Stopped() || ws.StopSignal() != 5 {
		t.Fatalf("we expected to hit a breakpoint, but did not.")
	}

	if err := debug.Unbreak(inferior, bp); err != nil {
		t.Fatalf("unsetting breakpoint for malloc: %v\n", err)
	}
	if err := debug.Stepback(inferior); err != nil {
		t.Fatal(err)
	}

	// now the program should run until completion.
	err = inferior.Continue()
	if err != nil {
		t.Fatalf("continuing failed: %v\n", err)
	}

	status = <-inferior.Events()
	if !(status.(syscall.WaitStatus)).Exited() {
		t.Fatalf("program did not end?")
	}
}

var garbage []Symbol

func BenchmarkSymbols(b *testing.B) {
	uvfc := "/home/tfogal/dev/iv3d/CmdLineConverter/Build/uvfconvert"
	sym, err := Symbols(uvfc)
	if err != nil {
		b.Fatalf("error loading symbols: %v\n", err)
	}
	garbage = sym
}

func BenchmarkSymbolsProcess(t *testing.B) {
	argv := []string{"../testprograms/dimensional", "3"}
	inferior, err := ptrace.Exec(argv[0], argv)
	if err != nil {
		t.Fatalf("could not start subprocess, bailing: %v", err)
	}
	defer inferior.Close()

	// wait for 1 event, i.e. the notification that the child has exec'd
	status := <-inferior.Events()
	if status == nil {
		t.Fatalf("no events?")
	}
	// wait until main so that the dynamic loader can run.
	assert(addr_main(argv[0]) != 0x0)
	debug.WaitUntil(inferior, addr_main(argv[0]))

	SymbolsProcess(inferior)
	inferior.SendSignal(syscall.SIGKILL)
}

// simple test to make sure the C bindings to offsetof() are valid.
func TestLmapOffsets(t *testing.T) {
	if lname_offset() >= lnext_offset() {
		t.Fatalf("lname offset (%d) should be l.t. lnext offset (%d)",
			lname_offset(), lnext_offset())
	}
}

func TestFind(t *testing.T) {
	slist := []Symbol{
		{"__MAIN", 0x400120, 0},
		{"zend", 0x23491, 0},
		{"abc", 0x400220, 0},
		{"nothing", 0x4008123, 0},
		{"def", 0x400320, 0},
		{"ghi", 0x400340, 0},
		{"GHI", 0x400840, 0},
	}
	sort.Sort(SymList(slist))
	garbage := find_symbol("garbage", slist)
	if garbage != nil {
		t.Fatalf("garbage (%s) found but it's not in the list\n", garbage.Name())
	}
}
