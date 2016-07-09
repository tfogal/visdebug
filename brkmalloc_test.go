package main

import "errors"
import "log"
import "testing"
import "./bfd"
import "./debug"
import "./msg"
import "github.com/tfogal/ptrace"

var tst = msg.StdChan("testing")

func addr_main(program string) uintptr {
	symbols, err := bfd.Symbols(program)
	if err != nil {
		log.Fatalf("err: %v\n", err)
	}

	symmain := symbol("main", symbols)
	return symmain.Address()
}

func startproc(argv []string) (*ptrace.Tracee, error) {
	inferior, err := ptrace.Exec(argv[0], argv)
	if err != nil {
		return nil, err
	}
	/* wait for 1 event, i.e. the notification that the child has exec'd */
	status := <-inferior.Events()
	if status == nil {
		inferior.Close()
		return nil, errors.New("no events?")
	}

	debug.WaitUntil(inferior, addr_main(argv[0]))

	return inferior, nil
}

func TestBreakMalloc(t *testing.T) {
	argv := []string{"./testprograms/pauser", "3"}
	inferior, err := startproc(argv)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	symbols, err := bfd.SymbolsProcess(inferior)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	malloc := bfd.Symbol{}
	for _, sym := range symbols {
		if sym.Name() == "malloc" {
			malloc = sym
		}
	}
	tst.Printf("malloc is at 0x%x\n", malloc.Address())
}
