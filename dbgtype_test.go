package main

import "errors"
import "fmt"
import "io"
import "testing"
import "./bfd"
import "./cfg"
import "./debug"
import "github.com/tfogal/ptrace"
import "code.google.com/p/rsc.x86/x86asm"

func init() {
	globals = CmdGlobal{"testprograms/dimensional", nil, nil, 0}
}

func TestDimsType(t *testing.T) {
	d, err := dbg_gvar_basetype(globals.program, 0x602070)
	if err != nil {
		t.Fatalf("func failed: %v\n", err)
	}
	dims := d.Common()
	if dims.ByteSize != 8 {
		t.Fatalf("byte size %v instead of 8\n", dims.ByteSize)
	}
	if dims.Name != "long unsigned int" { // aka size_t
		t.Fatalf("base type not 'long unsigned int': %v\n", dims.Name)
	}
}

func TestSymExec(t *testing.T) {
	argv := []string{"testprograms/dimensional", "3"}
	inferior, err := ptrace.Exec(argv[0], argv)
	if err != nil {
		t.Fatalf("could not start process: %v\n", err)
	}
	<-inferior.Events() // eat "starting..."
	defer inferior.Close()

	if err := MainSync(argv[0], inferior); err != nil {
		t.Fatalf("executing up to main: %v\n", err)
	}

	symbs, err := bfd.SymbolsProcess(inferior)
	if err != nil {
		t.Fatalf("could not read symbols: %v\n", err)
	}

	smooth3 := symbol("smooth3", symbs)
	if smooth3 == nil {
		t.Fatalf("could not find 'smooth3' function!\n")
	}

	graph := cfg.FromAddress(argv[0], smooth3.Address())
	if graph == nil {
		t.Fatalf("smooth3 in symbtab but not CFG?\n")
	}
	rn := root_node(graph, smooth3)
	cfg.Analyze(rn)

	seen := make(map[uintptr]bool)
	for _, bb := range graph {
		if bb.LoopHeader() || seen[bb.Addr] {
			continue
		}
		seen[bb.Addr] = true
		if err := testsymex(inferior, bb); err != nil {
			t.Fatalf("error on hdr %s(0x%0x): %v\n", bb.Name, bb.Addr, err)
		}
	}
}

func testsymex(inferior *ptrace.Tracee, bb *cfg.Node) error {
	if bb.LoopHeader() {
		panic("don't give this a loop header!")
	}
	for _, hdr := range bb.Headers {
		if err := debug.WaitUntil(inferior, hdr.Addr); err != nil {
			return fmt.Errorf("never reached hdr 0x%0x: %v\n", hdr.Addr, err)
		}
		insn_regs, err := symexec(inferior, hdr.Addr)
		if err != nil {
			return err
		}

		// Now, find the CMP instruction that should be in the basic block.
		_, cmpaddr, err := find_2arg([]x86asm.Op{x86asm.CMP}, inferior, hdr.Addr)
		if err == io.EOF { // no such instruction?
			return errors.New("no CMP instruction in loop header BB?")
		}
		if err != nil {
			return err
		}

		// find the CMP instruction in there.
		var rf register_file
		for _, r := range insn_regs {
			if uintptr(r[x86asm.RIP].(memaddr)) == cmpaddr {
				rf = r
				break
			}
		}
		if rf == nil {
			return errors.New("no CMP setting?")
		}
		tst.Trace("%v\n", rf)
	}
	return nil
}
