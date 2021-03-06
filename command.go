/* Distributed under the MIT license.  See the LICENSE file.
 * Copyright (c) 2014--2016 Thomas Fogal */
// Houses the commands we use in our interactive debugging mode.
package main

import "bufio"
import "bytes"
import "debug/dwarf"
import "debug/elf"
import "encoding/binary"
import "errors"
import "fmt"
import "io"
import "os"
import "os/exec"
import "sort"
import "strconv"
import "strings"
import "syscall"
import "github.com/tfogal/ptrace"
import "code.google.com/p/rsc.x86/x86asm"
import "./bfd"
import "./cfg"
import "./debug"
import "./msg"

type CmdGlobal struct {
	program     string       // the filename for the program we are running
	symbols     []bfd.Symbol // the list of symbols from the process
	symbolsAddr []bfd.Symbol // list of symbols, sorted by address.
	minsize     uint
}

// initialization info that commands might want to use.
var globals CmdGlobal

// logging type information
var typeinfo = msg.StdChan("typeinfo")

func verify_symbols_loaded(inferior *ptrace.Tracee) error {
	if globals.symbols == nil {
		var err error // so we can use "=" and ensure 'symbols' is the global.
		globals.symbols, err = bfd.SymbolsProcess(inferior)
		if err != nil {
			return err
		}
	}
	return nil
}

type Command interface {
	Execute(*ptrace.Tracee) error
}

type cgeneric struct {
	args []string
}

func (c cgeneric) Execute(proc *ptrace.Tracee) error {
	fmt.Printf("unknown cmd: %s\n", c.args)
	return nil
}

type ccontinue struct {
	args []string
}

func (c ccontinue) Execute(proc *ptrace.Tracee) error {
	fmt.Printf("continuing ... %v\n", c.args)
	err := proc.Continue()
	return err
}

type cstep struct{} // needs no args.
func (c cstep) Execute(proc *ptrace.Tracee) error {
	err := proc.SingleStep()
	return err
}

type cstop struct{}

func (c cstop) Execute(proc *ptrace.Tracee) error {
	err := proc.SendSignal(syscall.SIGSTOP)
	return err
}

type cpid struct{}

func (c cpid) Execute(proc *ptrace.Tracee) error {
	fmt.Printf("%d\n", proc.PID())
	return nil
}

type cstatus struct{}

func (c cstatus) Execute(proc *ptrace.Tracee) error {
	fn := fmt.Sprintf("/proc/%d/stat", proc.PID())
	file, err := os.Open(fn)
	if err != nil {
		return err
	}
	defer file.Close()
	var pid int
	var name string
	var state rune
	n, err := fmt.Fscanf(file, "%d %s %c", &pid, &name, &state)
	if err != nil {
		return err
	}
	if n <= 1 {
		return errors.New("could not scan enough")
	}
	fmt.Printf("process %d is ", proc.PID())
	switch state {
	case 'D':
		fmt.Printf("in uninterruptible sleep (io?)\n")
		break
	case 'R':
		fmt.Printf("running\n")
		break
	case 'S':
		fmt.Printf("sleeping\n")
		break
	case 't':
		fmt.Printf("stopped (tracing)\n")
		break
	case 'W':
		fmt.Printf("(impossibly) paging\n")
		break
	case 'X':
		fmt.Printf("(impossibly) dead\n")
		break
	case 'Z':
		fmt.Printf("awaiting reaping.\n")
		break
	default:
		fmt.Printf("unknown?!\n")
		break
	}
	return nil
}

type cquit struct{}

func (c cquit) Execute(proc *ptrace.Tracee) error {
	if err := proc.SendSignal(syscall.SIGKILL); err != nil {
		return err
	}
	return nil
}

type cwait struct {
	funcname string
}

func (c cwait) Execute(inferior *ptrace.Tracee) error {
	if err := verify_symbols_loaded(inferior); err != nil {
		return err
	}
	// they can give us either an address or the name of an actual function.
	address := uintptr(0x0)
	if len(c.funcname) > 2 && c.funcname[0:2] == "0x" {
		saddr, err := strconv.ParseInt(c.funcname, 0, 64)
		if err != nil {
			return err
		}
		if saddr < 0 {
			panic("address cannot be negative, that makes no sense.")
		}
		address = uintptr(saddr)
	} else {
		sym := symbol(c.funcname, globals.symbols) // symbol lookup
		if sym == nil {
			return fmt.Errorf("could not find '%s' among the %d known symbols.",
				c.funcname, len(globals.symbols))
		}
		address = sym.Address()
	}
	err := debug.WaitUntil(inferior, address)
	if err == io.EOF {
		fmt.Printf("Program ended before '%s' was hit.\n", c.funcname)
		return nil
	}
	if err != nil {
		return err
	}
	return nil
}

type cparseerror struct {
	reason string
}

func (c cparseerror) Execute(*ptrace.Tracee) error {
	return fmt.Errorf("parse error: %s", c.reason)
}

type cregisters struct {
	regname string
}

func (c cregisters) Execute(inferior *ptrace.Tracee) error {
	regs, err := inferior.GetRegs()
	if err != nil {
		return err
	}

	wd, err := inferior.ReadWord(uintptr(regs.Rip))
	if err != nil {
		return err
	}

	switch c.regname {
	case "":
		fmt.Printf("%9s %14s %14s %13s %21s\n", "iptr", "RAX", "RBP", "RSP",
			"next-opcode")
		fmt.Printf("0x%012x 0x%012x 0x%012x 0x%012x 0x%012x\n", regs.Rip, regs.Rax,
			regs.Rbp, regs.Rsp, wd)
	case "rax":
		fmt.Printf("0x%012x\n", regs.Rax)
	case "rbx":
		fmt.Printf("0x%012x\n", regs.Rbx)
	case "rcx":
		fmt.Printf("0x%012x\n", regs.Rcx)
	case "rdx":
		fmt.Printf("0x%012x\n", regs.Rdx)
	case "rdi":
		fmt.Printf("0x%012x\n", regs.Rdi)
	case "rsi":
		fmt.Printf("0x%012x\n", regs.Rsi)
	case "r8":
		fmt.Printf("0x%012x\n", regs.R8)
	case "r9":
		fmt.Printf("0x%012x\n", regs.R9)
	case "r10":
		fmt.Printf("0x%012x\n", regs.R10)
	case "r11":
		fmt.Printf("0x%012x\n", regs.R11)
	case "r12":
		fmt.Printf("0x%012x\n", regs.R12)
	case "r13":
		fmt.Printf("0x%012x\n", regs.R13)
	case "r14":
		fmt.Printf("0x%012x\n", regs.R14)
	case "r15":
		fmt.Printf("0x%012x\n", regs.R15)
	}
	return nil
}

type csymbol struct {
	symname string
}

func (c csymbol) Execute(inferior *ptrace.Tracee) error {
	if err := verify_symbols_loaded(inferior); err != nil {
		return err
	}
	sym := symbol(c.symname, globals.symbols) // symbol lookup
	if sym == nil {
		return fmt.Errorf("could not find '%s' among the %d known symbols.",
			c.symname, len(globals.symbols))
	}
	fmt.Printf("'%s' is at 0x%012x\n", sym.Name(), sym.Address())
	return nil
}

type cderef struct {
	addr string // really, a uintptr, but do the parsing in the command.
}

func (c cderef) Execute(inferior *ptrace.Tracee) error {
	if c.addr == "" {
		return errors.New("empty address given")
	}
	ui, err := strconv.ParseUint(c.addr, 0, 64)
	if err != nil {
		return err
	}
	address := uintptr(ui)

	fmt.Printf("addr: 0x%0x\n", address)

	word, err := inferior.ReadWord(address)
	if err != nil {
		return err
	}

	fmt.Printf("0x%0x\n", word)
	return nil
}

// need these to be able to sort symbols on addresses.
type SymListA []bfd.Symbol

func (s SymListA) Len() int { return len(s) }
func (s SymListA) Less(i int, j int) bool {
	return s[i].Address() < s[j].Address()
}
func (s SymListA) Swap(i int, j int) { s[i], s[j] = s[j], s[i] }

// find what function the given address is in.
func find_function(address uintptr) (*bfd.Symbol, error) {
	if len(globals.symbols) == 0 {
		return nil, errors.New("symbol list is empty, forgot to load them?")
	}
	if globals.symbolsAddr == nil {
		// copy our symlist to a new variable so that we can change the sort order
		// to be addresses instead of names without mucking up our normal table.
		globals.symbolsAddr = make([]bfd.Symbol, len(globals.symbols))
		copy(globals.symbolsAddr, globals.symbols)
		sort.Sort(SymListA(globals.symbolsAddr))
	}

	// We can't use sort.Search here because 'address' can be in the middle of a
	// function, and we don't have an entry for every possible address.  We just
	// want to find the "minimum" address we are in.
	fidx := 0
	for i, sy := range globals.symbolsAddr { // todo binary search
		if sy.Address() <= address {
			fidx = i
		}
		if sy.Address() > address {
			break
		} // will never find anything
	}
	if fidx >= len(globals.symbolsAddr) ||
		globals.symbolsAddr[fidx].Address() > address {
		return nil, fmt.Errorf("addr 0x%0x not found in %d-symbol list", address,
			len(globals.symbolsAddr))
	}
	if globals.symbolsAddr[fidx].Address() == 0x0 {
		return nil,
			errors.New("we are near NULL?  I don't believe it, probably a bug.")
	}
	if globals.symbolsAddr[fidx].Name() == "" {
		return nil, errors.New("insn ptr is in no man's land.")
	}
	return &globals.symbolsAddr[fidx], nil
}

// identifies the root node (function entry point) of the graph
func root_node(graph map[uintptr]*cfg.Node, symb *bfd.Symbol) *cfg.Node {
	for _, v := range graph {
		if v.Name == symb.Name() || v.Addr == symb.Address() {
			return v
		}
	}
	return nil
}

func viewcfg(filename string) {
	cmd := exec.Command("viewcfg", filename)
	cmd.Start()
}

// build CFG for local function
type ccfg struct {
	filename string // output to this file, if set.
}

func (c ccfg) Execute(inferior *ptrace.Tracee) error {
	// cfg.FromAddress needs the entry point of the function.
	// Thus we need to identify where we are within the execution.
	symb, err := where(inferior)
	if err != nil {
		return err
	}

	graph := cfg.FromAddress(globals.program, symb.Address())
	// sometimes it seems we are unable to find the root node.  this appears to
	// only happen if the function lives in a stripped shared library.
	if rn := root_node(graph, symb); rn != nil {
		cfg.Analyze(rn)
		// output to a file that defaults to stdout.  But 'inorder' needs a
		// 1-argument function, so construct a closure around the appropriate
		// writer.
		writer := os.Stdout
		if c.filename != "" {
			writer, err = os.OpenFile(c.filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
				0666)
			if err != nil {
				return err
			}
		}
		printer := func(node *cfg.Node) { dotNode(node, writer) }
		// graphviz doesn't accept "."s in a name, yet gcc sometimes creates
		// symbols with "."s in them.  filter them out.
		name := strings.Replace(symb.Name(), ".", "_", -1)
		name = strings.Replace(name, "-", "_", -1) // ditto for "-"
		fmt.Fprintf(writer, "digraph %s {\n", name)
		fmt.Fprintf(writer, "\tranksep=\"0.2 equally\";\n\tratio=0.7;\n")
		inorder(graph, printer)
		fmt.Fprintf(writer, "}\n")
		if writer != os.Stdout {
			if err := writer.Close(); err != nil {
				return err
			}
			fmt.Printf("Output '%s' successfully created.\n", c.filename)
			viewcfg(c.filename)
		}
	} else {
		fmt.Printf("Cannot find root node of %d-element graph!\n", len(graph))
		fmt.Printf("This likely means the function is in a stripped shared ")
		fmt.Printf("library.  Build the library with debug symbols and do not ")
		fmt.Printf("strip it if you'd like to be able to generate this CFG.\n")
	}
	return nil
}

// print out the list of known symbols.
type csymlist struct{}

func (csymlist) Execute(inferior *ptrace.Tracee) error {
	if err := verify_symbols_loaded(inferior); err != nil {
		return err
	}

	n := 0
	for _, s := range globals.symbols {
		if s.Name() == "" {
			continue
		} // stupid "blank" symbols, WTF are these??
		if n+1+len(s.Name()) > 80 {
			fmt.Printf("\n")
			n = 0
		}
		nbytes, err := fmt.Printf("%s ", s.Name())
		if err != nil {
			return err
		}

		n += nbytes
	}
	fmt.Printf("\n")
	return nil
}

// identifies the function the inferior is currently located in.
func where(inferior *ptrace.Tracee) (*bfd.Symbol, error) {
	if err := verify_symbols_loaded(inferior); err != nil {
		return nil, err
	}
	regs, err := inferior.GetRegs()
	if err != nil {
		return nil, err
	}

	symbol, err := find_function(uintptr(regs.Rip))
	if err != nil {
		return nil, err
	}
	return symbol, nil
}

// maps the current instruction pointer to a function and then tells the user
// where they are.
type cwhereami struct{}

func (cwhereami) Execute(inferior *ptrace.Tracee) error {
	symb, err := where(inferior)
	if err != nil {
		return err
	}
	iptr, err := inferior.GetIPtr()
	if err != nil {
		return err
	}

	diff := iptr - symb.Address()
	fmt.Printf("0x%012x  %s+%d\n", iptr, symb.Name(), diff)
	return nil
}

func conditional_jump(ixn x86asm.Inst) bool {
	return ixn.Op == x86asm.JA || ixn.Op == x86asm.JAE || ixn.Op == x86asm.JB ||
		ixn.Op == x86asm.JBE || ixn.Op == x86asm.JCXZ ||
		ixn.Op == x86asm.JE || ixn.Op == x86asm.JECXZ || ixn.Op == x86asm.JG ||
		ixn.Op == x86asm.JGE || ixn.Op == x86asm.JL || ixn.Op == x86asm.JLE ||
		ixn.Op == x86asm.JNE || ixn.Op == x86asm.JNO || ixn.Op == x86asm.JNP ||
		ixn.Op == x86asm.JNS || ixn.Op == x86asm.JO || ixn.Op == x86asm.JP ||
		ixn.Op == x86asm.JRCXZ || ixn.Op == x86asm.JS
}

// prints out the assembly starting at a given node, until we hit a
// conditional jump.
func disassemble_cond(inferior *ptrace.Tracee, node *cfg.Node) error {
	addr := node.Addr
	insn := make([]byte, 16) // max length of x86-64 insn is 16 bytes.

	// run through the block until we find a conditional jump, disassembling each
	// instruction as we go.  this is complicated slightly by unconditional
	// jumps: we need to be sure to follow them.
	for {
		if err := inferior.Read(addr, insn); err != nil {
			return err
		}

		ixn, err := x86asm.Decode(insn, 64)
		if err != nil {
			return err
		}
		fmt.Printf("0x%08x: %-25v | %-34s\n", addr, ixn, x86asm.IntelSyntax(ixn))

		if conditional_jump(ixn) { // jump instruction.  basic block is done.
			break
		}
		addr += uintptr(ixn.Len)
		if ixn.Op == x86asm.JMP { // also follow jumps!
			fmt.Printf("jmp!  args: %v\n", ixn.Args[0])
			addr += uintptr(ixn.Args[0].(x86asm.Rel))
		}
	}
	return nil
}

type cdisassemble struct{}

func (cdisassemble) Execute(inferior *ptrace.Tracee) error {
	symb, err := where(inferior)
	if err != nil {
		return err
	}

	graph := cfg.FromAddress(globals.program, symb.Address())
	if len(graph) == 0 {
		return fmt.Errorf("could not build local CFG for %s@0x%0x", symb.Name(),
			symb.Address())
	}
	if rn := root_node(graph, symb); rn != nil {
		cfg.Analyze(rn)
	}

	bb, err := basic_block(graph, whereis(inferior))
	if err != nil {
		return err
	}

	disassemble_cond(inferior, bb)
	return nil
}

// decodes the instruction[s] for the given loop header basic block.
type cdecode struct {
	addr string
}

func (c cdecode) Execute(inferior *ptrace.Tracee) error {
	address := uintptr(0x0)
	// accept "%reg" to mean 'grab the address of from the given register"
	if strings.Contains(c.addr, "%") { // register reference.
		regs, err := inferior.GetRegs()
		if err != nil {
			return err
		}
		switch c.addr {
		case "%rip":
			address = uintptr(regs.Rip)
		case "%rbp":
			address = uintptr(regs.Rbp)
		case "%rsp":
			address = uintptr(regs.Rsp)
		default:
			return fmt.Errorf("reg '%s' unknown.", c.addr)
		}
	} else {
		ui, err := strconv.ParseUint(c.addr, 0, 64)
		if err != nil {
			return err
		}
		address = uintptr(ui)
	}

	// max length of an instruction in x86-64 is 16 bytes (unconfirmed..).
	insn := make([]byte, 16)
	if err := inferior.Read(address, insn); err != nil {
		return err
	}

	ixn, err := x86asm.Decode(insn, 64)
	if err != nil {
		return err
	}
	fmt.Printf("insn: %v\n", ixn)

	return nil
}

// finds the basic block that the given address is part of
func basic_block(graph map[uintptr]*cfg.Node, address uintptr) (*cfg.Node, error) {
	closest_addr := uintptr(0x0)
	closest := (*cfg.Node)(nil)
	for addr, node := range graph {
		if addr <= address && addr > closest_addr {
			closest_addr = addr
			closest = node
		}
	}
	if closest == nil {
		return nil, fmt.Errorf("no reasonable BBs out of %d", len(graph))
	}
	return closest, nil
}

func print_bindlist(node *cfg.Node, inferior *ptrace.Tracee) {
	for _, hdr := range node.Headers {
		fmt.Printf("0x%08x", node.Addr)
		if node.LoopHeader() {
			fmt.Printf(",LH(%d)", node.Depth())
		} else {
			fmt.Printf("      ") // just keep it evenly spaced.
		}
		fmt.Printf(" is bound by 0x%0x", hdr.Addr)
		if hdr.LoopHeader() {
			fmt.Printf(",LHd(%d)", hdr.Depth())
		}
		fmt.Printf("\n")
		if hdr.LoopHeader() {
			disassemble_cond(inferior, hdr)
		}
		print_bindlist(hdr, inferior)
	}
}

// x86asm.Args is always 4 elements, regardless of how many arguments the
// instruction takes.  if it takes fewer than 4, the 'extra' arguments will be
// nil.
func nargs(args x86asm.Args) uint {
	n := uint(0)
	for _, a := range args {
		if a != nil {
			n++
		}
	}
	return n
}

func opcode_in(opcode x86asm.Op, ops []x86asm.Op) bool {
	for _, o := range ops {
		if o == opcode {
			return true
		}
	}
	return false
}

// starting from 'startaddr', find the next instruction which has the given
// opcode and 2 arguments, the first of which is the register given by 'reg'
// and the latter a memory reference.
// This will error out if it hits a conditional jump: start it from the basic
// block you care about.
func find_2regmem(opcodes []x86asm.Op, reg x86asm.Reg, startaddr uintptr,
	inferior *ptrace.Tracee) (x86asm.Inst, uintptr, error) {
	insn := make([]byte, 16)
	addr := startaddr
	bad := x86asm.Inst{} // just a constant to return on error.
	for {
		if err := inferior.Read(addr, insn); err != nil {
			return bad, 0x0, err
		}

		ixn, err := x86asm.Decode(insn, 64)
		if err != nil {
			return bad, 0x0, err
		}

		if conditional_jump(ixn) {
			return bad, 0x0, io.EOF // i.e. exited BB before hitting opcode.
		}

		if opcode_in(ixn.Op, opcodes) && nargs(ixn.Args) == 2 {
			_, isreg := ixn.Args[0].(x86asm.Reg)
			memref, ismem := ixn.Args[1].(x86asm.Mem)
			if isreg && ismem && memref.Base == reg {
				return ixn, addr, nil
			}
		}

		addr += uintptr(ixn.Len)
		if ixn.Op == x86asm.JMP {
			addr += uintptr(ixn.Args[0].(x86asm.Rel))
		}
	}
}

// searches for the instruction with the given opcode and 2 arguments
func find_2arg(opcodes []x86asm.Op, inferior *ptrace.Tracee,
	startaddr uintptr) (x86asm.Inst, uintptr, error) {
	insn := make([]byte, 16)
	addr := startaddr
	bad := x86asm.Inst{} // just a constant to return on error.
	for {
		if err := inferior.Read(addr, insn); err != nil {
			return bad, 0x0, err
		}

		ixn, err := x86asm.Decode(insn, 64)
		if err != nil {
			return bad, 0x0, err
		}

		if conditional_jump(ixn) {
			return bad, 0x0, io.EOF // i.e. exited BB before hitting opcode.
		}

		if opcode_in(ixn.Op, opcodes) && nargs(ixn.Args) == 2 {
			return ixn, addr, nil
		}

		addr += uintptr(ixn.Len)
		if ixn.Op == x86asm.JMP {
			addr += uintptr(ixn.Args[0].(x86asm.Rel))
		}
	}
}

// reads the inferior's memory according to the given memory reference.  the
// bits are copied into the uint64 retval; if the data are not a uint64, then
// you should cast it manually.
func readmem(memref x86asm.Mem, inferior *ptrace.Tracee) (uint64, error) {
	regs, err := inferior.GetRegs()
	if err != nil {
		return 0, fmt.Errorf("could not read regs: %v", err)
	}
	var mr int64
	switch memref.Base {
	case x86asm.RIP:
		mr = int64(regs.Rip)
	case x86asm.RBP:
		mr = int64(regs.Rbp)
	default:
		assert("unhandled case" == "false")
	}
	// clip to 32bit first, to make sure it gets proper sign extension.
	mr = mr + int64(int32(memref.Disp))
	/*
	   fmt.Printf("memref: seg: %v, base: %v, scale: %v, index: %v, disp: %d\n",
	              memref.Segment, memref.Base, memref.Scale, memref.Index,
	              int64(int32(memref.Disp)))
	   fmt.Printf("0x%0x + %v == 0x%0x\n", regval, int64(int32(memref.Disp)), mr)
	*/

	val, err := inferior.ReadWord(uintptr(mr))
	if err != nil {
		return 0, fmt.Errorf("reading value @ 0x%0x: %v", mr, err)
	}
	// We only use readmem to read index variables right now.  Most new code uses
	// 8-byte indices (i.e. a size_t on x86-64), but some really old code uses
	// plain 'int', 4 bytes on our target arch.
	// No sim actually *needs* 8-byte indices (remember this is in a *single*
	// dimension), so that means the high bits are almost 0.
	// ... but for really old code, the index is 4-bytes, and if "the next stuff"
	// in memory is non-zero at the time we read, then we'll grab that stuff.
	if int64(val) != int64(int32(val)) {
		typeinfo.Warn("4-byte index variable?  Might just be old code.\n")
	}
	return uint64(int64(int32(val))), nil
}

func readreg(regref x86asm.Reg, inferior *ptrace.Tracee) (uint64, error) {
	regs, err := inferior.GetRegs()
	if err != nil {
		return 0, err
	}

	var v uint64
	switch regref {
	case x86asm.RAX:
		v = regs.Rax
	case x86asm.EAX:
		v = regs.Rax & 0xffffffff
	case x86asm.RCX:
		v = regs.Rcx
	case x86asm.ECX:
		v = regs.Rcx & 0xffffffff
	case x86asm.RDX:
		v = regs.Rdx
	case x86asm.EDX:
		v = regs.Rdx & 0xffffffff
	case x86asm.RBX:
		v = regs.Rbx
	case x86asm.EBX:
		v = regs.Rbx & 0xffffffff
	case x86asm.RSP:
		v = regs.Rsp
	case x86asm.RBP:
		v = regs.Rbp
	case x86asm.EBP:
		v = regs.Rbp & 0xffffffff
	case x86asm.RSI:
		v = regs.Rsi
	case x86asm.ESI:
		v = regs.Rsi & 0xffffffff
	case x86asm.RDI:
		v = regs.Rdi
	case x86asm.EDI:
		v = regs.Rdi & 0xffffffff
	case x86asm.R8:
		v = regs.R8
	case x86asm.R9:
		v = regs.R9
	case x86asm.R10:
		v = regs.R10
	case x86asm.R11:
		v = regs.R11
	case x86asm.R12:
		v = regs.R12
	case x86asm.R13:
		v = regs.R13
	case x86asm.R14:
		v = regs.R14
	case x86asm.R15:
		v = regs.R15
	default:
		fmt.Printf("register: %v\n", regref)
		panic("unhandled case")
	}

	return v, nil
}

// The source of data in a register can be:
//   just a pure constant
//   a raw memory address, usually indicating a global variable
//   a framepointer-relative address (local variables only)
type regsource interface {
	isRegSource()
	String() string
}
type constval uint64
type memaddr uintptr
type lvar int64 // lvar's are always fptr relative; we just store the relation
type unknown struct{}

func (constval) isRegSource() {}
func (c constval) String() string {
	return fmt.Sprintf("$0x%0x", uint64(c))
}
func (memaddr) isRegSource() {}
func (m memaddr) String() string {
	return fmt.Sprintf("0x%0x", uintptr(m))
}
func (lvar) isRegSource() {}
func (l lvar) String() string {
	rel := int64(l)
	if rel >= 0 {
		return fmt.Sprintf("[FPtr+%d]", rel)
	}
	return fmt.Sprintf("[FPtr%d]", rel)
}
func (unknown) isRegSource() {}
func (u unknown) String() string {
	return "unknown"
}

// this usually won't have entries for every register; lots of registers are
// meaningless for our analysis.
type register_file map[x86asm.Reg]regsource

// This was made specifically to match the format of a kernel oops, so that
// readers of those dumps would feel at home.
func (rf register_file) String() string {
	s := make([]string, 0)
	s = append(s, fmt.Sprintf("RIP: %14v  RSP: %14v  RFLAGS: %14v",
		rf[x86asm.RIP], rf[x86asm.RSP], 0x0))
	s = append(s, fmt.Sprintf("RAX: %14v  RBX: %14v  RCX: %14v",
		rf[x86asm.RAX], rf[x86asm.RBX], rf[x86asm.RCX]))
	s = append(s, fmt.Sprintf("RDX: %14v  RSI: %14v  RDI: %14v",
		rf[x86asm.RDX], rf[x86asm.RSI], rf[x86asm.RDI]))
	s = append(s, fmt.Sprintf("RBP: %14v   R8: %14v   R9: %14v",
		rf[x86asm.RBP], rf[x86asm.R8], rf[x86asm.R9]))
	s = append(s, fmt.Sprintf("R10: %14v  R11: %14v  R12: %14v",
		rf[x86asm.R10], rf[x86asm.R11], rf[x86asm.R12]))
	s = append(s, fmt.Sprintf("R13: %14v  R14: %14v  R15: %14v",
		rf[x86asm.R13], rf[x86asm.R14], rf[x86asm.R15]))
	return strings.Join(s, "\n")
}

// x64-64 "mov"e instructions always have two operands: a source and a
// target/destination.  This returns the source argument.
func movsource(ixn x86asm.Inst) x86asm.Arg {
	if ixn.Op != x86asm.MOV {
		panic("should have been given a MOV instruction.")
	}
	return ixn.Args[1]
}

// x64-64 "mov"e instructions always have two operands: a source and a
// target/destination.  This identifies the target operand and assumes it is a
// register.  Bad things (tm) happen if it is not.
func movregtarget(ixn x86asm.Inst) x86asm.Reg {
	if ixn.Op != x86asm.MOV {
		panic("should have been given a MOV instruction.")
	}
	_, isreg := ixn.Args[0].(x86asm.Reg)
	if !isreg {
		panic("target is not a register!  this is possible??")
	}
	return ixn.Args[0].(x86asm.Reg)
}

var symlog = msg.StdChan("symlog")

// symbolic execution of the inferior from the given address until the end of
// its basic block.  For each assembly instruction we keep track of the
// register data / source of its data.
func symexec(inferior *ptrace.Tracee, addr uintptr) ([]register_file, error) {
	insn := make([]byte, 16) // max length of an x86-64 insn is 16 bytes.
	rfile := make([]register_file, 0)

	{ // Just for sanity's sake.
		// Better: if iptr != addr, then we just initialize all the registers with
		// unknown and return an error if an instruction makes e.g. a frame-relative
		// reference (since we won't know RBP).
		iptr, err := inferior.GetIPtr()
		if err != nil {
			return nil, err
		}
		if iptr != addr {
			return nil, fmt.Errorf("iptr @ 0x%0x but addr is 0x%0x!\n", iptr, addr)
		}
	}

	// foreach instruction until we exit the basic block...
	for {
		if err := inferior.Read(addr, insn); err != nil {
			return nil, err
		}

		ixn, err := x86asm.Decode(insn, 64)
		if err != nil {
			return nil, err
		}

		rf := make(register_file)
		if len(rfile) == 0 { // first instruction, initialize to unknowns
			rf[x86asm.R8] = unknown{}
			rf[x86asm.R9] = unknown{}
			rf[x86asm.R10] = unknown{}
			rf[x86asm.R11] = unknown{}
			rf[x86asm.R12] = unknown{}
			rf[x86asm.R13] = unknown{}
			rf[x86asm.R14] = unknown{}
			rf[x86asm.R15] = unknown{}
			// we'll set RBP below, ignore it for now.
			rf[x86asm.RBX] = unknown{}
			rf[x86asm.RAX] = unknown{}
			rf[x86asm.RCX] = unknown{}
			rf[x86asm.RDX] = unknown{}
			rf[x86asm.RSI] = unknown{}
			rf[x86asm.RDI] = unknown{}
			// ditto for setting RIP.
			rf[x86asm.RSP] = unknown{}
			regs, err := inferior.GetRegs()
			if err != nil {
				return nil, err
			}
			rf[x86asm.RBP] = memaddr(regs.Rbp)
			rf[x86asm.RAX] = memaddr(regs.Rax)
		} else {
			// initialize values with those from previous instruction
			for k, val := range rfile[len(rfile)-1] {
				rf[k] = val
			}
		}
		rf[x86asm.RIP] = memaddr(addr)

		symlog.Trace("0x%08x: %v\n", addr, ixn)
		if ixn.Op == x86asm.MOV {
			src := movsource(ixn)
			srcreg, src_isreg := src.(x86asm.Reg)
			memref, src_ismem := src.(x86asm.Mem)
			srcconst, src_isconst := src.(x86asm.Imm)
			if src_isconst {
				rf[movregtarget(ixn)] = constval(srcconst)
			} else if src_isreg {
				rf[movregtarget(ixn)] = rf[srcreg]
			} else if src_ismem {
				if memref.Base == x86asm.RIP {
					rf[movregtarget(ixn)] = memaddr(int64(addr) + int64(ixn.Len) +
						memref.Disp)
				} else if memref.Base == x86asm.RBP {
					rf[movregtarget(ixn)] = lvar(int32(memref.Disp))
				} else {
					refconst, ref_isconst := rf[memref.Base].(constval)
					refaddr, ref_isaddr := rf[memref.Base].(memaddr)
					refvar, ref_isvar := rf[memref.Base].(lvar)
					if ref_isconst {
						rf[movregtarget(ixn)] = refconst
					} else if ref_isaddr {
						rf[movregtarget(ixn)] = refaddr
						// I want to see an example in the wild; make it stand out for now
						// by returning an error so i can examine this when it happens.
						return nil, fmt.Errorf("not sure this is right, being cautious..")
					} else if ref_isvar {
						rf[movregtarget(ixn)] = refvar
					} else {
						// if it's a reference to a reference, then we'd need to repeat
						// this whole if crap.. again.  we should really have made this
						// a method and recursed.. but instead it's just hacked, and
						// thus broken if we get here.
						return nil, fmt.Errorf("recursion too shallow.")
					}
				}
			}
			//symlog.Trace("%v\n", rf)
		}
		rfile = append(rfile, rf)

		if conditional_jump(ixn) { // jump instruction.  basic block is done.
			break
		}
		addr += uintptr(ixn.Len)
		if ixn.Op == x86asm.JMP { // also follow jumps!
			fmt.Printf("jmp-ing!  args: %v\n", ixn.Args[0])
			addr += uintptr(ixn.Args[0].(x86asm.Rel))
		}
	}
	return rfile, nil
}

type value struct {
	v   uint64
	typ debug.Type
}

// identifies the larger of the two 'value's.  it is assumed that these are
// arguments for a loop index that describes a data array.  if that's the case,
// then they are positive.. even if they are stored in signed containers.  if
// they weren't positive, then that'd mean we had loop indices like this:
//   for(int x=whatever; x > -42; x--) { ... }
// which is of course implausible in a simulation program, at least in loops
// we'd care about.
func maxvalue(args [2]value) int64 {
	if args[0].typ.Type == nil || args[1].typ.Type == nil {
		typeinfo.Trace("no type information, pretending both are signed")
		v1 := int64(args[0].v)
		v2 := int64(args[1].v)
		if v1 > v2 {
			return v1
		}
		return v2
	} else if !args[0].typ.Signed() && !args[1].typ.Signed() { // both unsigned
		typeinfo.Trace("Both values are unsigned, assuming they are uint64s.")
		if args[0].v > args[1].v {
			return int64(args[0].v)
		}
		return int64(args[1].v)
	} else { // at least one is signed.  just cast them both to signed.
		typeinfo.Trace("One or both values are signed.")
		v1 := int64(args[0].v)
		v2 := int64(args[1].v)
		if v1 > v2 {
			return v1
		}
		return v2
	}
}

// given a (CMP) instruction and its corresponding register_file setting from
// symbolic execution, give back the two values that are its arguments.
func readargs(ixn x86asm.Inst, rf register_file, fqn string,
	inferior *ptrace.Tracee) ([2]value, error) {
	bad := [2]value{value{}, value{}}
	var err error

	values := [2]value{}
	values[0], err = readvalue(ixn.Args[0], ixn.Len, rf, fqn, inferior)
	if err != nil {
		return bad, err
	}
	typeinfo.Trace("read value 0: %d, %v\n", values[0].v, values[0].typ)
	values[1], err = readvalue(ixn.Args[1], ixn.Len, rf, fqn, inferior)
	if err != nil {
		return bad, err
	}
	typeinfo.Trace("read value 1: %d, %v\n", values[1].v, values[1].typ)

	return values, nil
}

// gives back a 'value' for the given argument of an instruction.
func readvalue(arg x86asm.Arg, ixnlen int, rf register_file, fqn string,
	inferior *ptrace.Tracee) (value, error) {
	reg, isreg := arg.(x86asm.Reg)
	if isreg {
		lv, src_local := rf[reg].(lvar)
		maddr, src_memaddr := rf[reg].(memaddr)

		var typ debug.Type
		var err error
		if src_local {
			typ, err = debug.TypeLocal(globals.program, fqn, int64(lv))
			if err != nil {
				typeinfo.Warn("Lvar type (%s, 0x%0x) lookup error: %v\n", fqn,
					int64(lv), err)
				typ = debug.Type{}
			}
		}
		if src_memaddr {
			typ, err = debug.TypeGlobalVar(globals.program, uintptr(maddr))
			if err != nil {
				typeinfo.Warn("Gvar (0x%0x) lookup error: %v\n", uintptr(maddr), err)
				typ = debug.Type{}
			}
		}

		regarg, err := readreg(reg, inferior)
		if err != nil {
			return value{}, err
		}
		return value{v: regarg, typ: typ}, nil
	}

	mem, ismem := arg.(x86asm.Mem)
	if ismem {
		// insn ptr addresses are relative to the NEXT instruction, not this one.
		if mem.Base == x86asm.RIP {
			mem.Disp += int64(ixnlen)
		}

		memarg, err := readmem(mem, inferior)
		if err != nil {
			return value{}, err
		}
		if mem.Base == x86asm.RBP {
			typ, err := debug.TypeLocal(globals.program, fqn, int64(int32(mem.Disp)))
			if err != nil {
				typeinfo.Warn("lvar type (%s, 0x%0x) lookup error: %v\n", fqn,
					int32(mem.Disp), err)
				typ = debug.Type{}
			}
			return value{v: memarg, typ: typ}, nil
		}
		if mem.Base == x86asm.RIP {
			address := int64(rf[x86asm.RIP].(memaddr)) + mem.Disp
			typ, err := debug.TypeGlobalVar(globals.program, uintptr(address))
			if err != nil {
				typeinfo.Warn("gvar (0x%0x) lookup error: %v\n", uintptr(address), err)
				typ = debug.Type{}
			}
			return value{v: memarg, typ: typ}, nil
		}
	}
	imm, isconst := arg.(x86asm.Imm)
	if isconst {
		// how can we construct a proper type here?  there is none, really.
		return value{v: uint64(imm), typ: debug.Type{}}, nil
	}
	return value{}, fmt.Errorf("insn '%v' is not reg, mem, or imm", arg)
}

// finds the register file associated with the given instruction.
func rfaddr(insns []register_file, addr uintptr) register_file {
	for _, r := range insns {
		if uintptr(r[x86asm.RIP].(memaddr)) == addr {
			return r
		}
	}
	return nil
}

// identify the bounds of the loop[s] of where we are now.
// note this will execute the inferior a little bit.
func bind_identify(fqn string, node *cfg.Node,
	inferior *ptrace.Tracee) ([]uint, error) {
	dims := make([]uint, 0)
	assert(len(node.Headers) <= 1) // seems to always be the case.  need loop?
	for _, hdr := range node.Headers {
		if !hdr.LoopHeader() {
			panic("non-header in header list!")
		}

		// We'll look for the "CMP" instruction in the loop header in a second: one
		// of the operands of that instruction will tell us what the loop bound is.
		// To identify the signedness of that operand, however, we need to know
		// where it came from.  For that, we symbolically execute the basic block.
		// That symbolic execution works a lot better if we can initialize the
		// register set with *actual* values, but to do that we'd need to know the
		// set of values on entry to the basic block.
		// So: execute up until the basic block.
		if err := debug.WaitUntil(inferior, hdr.Addr); err != nil {
			return nil, fmt.Errorf("waiting for loop header: %v", err)
		}
		insn_regs, err := symexec(inferior, hdr.Addr)
		if err != nil {
			return nil, err
		}

		// Now, find the CMP instruction that should be in the basic block.
		ixn, cmpaddr, err := find_2arg([]x86asm.Op{x86asm.CMP}, inferior, hdr.Addr)
		if err == io.EOF { // no such instruction, let's go for a different case.
			return nil, errors.New("no CMP instruction in loop header BB?")
		}
		if err != nil {
			return nil, err
		}

		// execute up until the comp, so registers/mem are valid to read
		if err := debug.WaitUntil(inferior, cmpaddr); err != nil {
			return nil, err
		}
		if ixn.Op != x86asm.CMP {
			panic("not at CMP instruction?")
		}

		// which entry in insn_regs is for the CMP instruction?
		rf := rfaddr(insn_regs, cmpaddr)
		if rf == nil {
			panic("compare addr not found, broken logic.")
		}

		values, err := readargs(ixn, rf, fqn, inferior)
		if err != nil {
			return nil, err
		}
		larger := maxvalue(values)

		dims = append(dims, uint(larger))

		subdims, err := bind_identify(fqn, hdr, inferior)
		if err != nil {
			return nil, err
		}
		for _, x := range subdims {
			dims = append(dims, x)
		}
	}
	return dims, nil
}

// Looks up the type of a global variable in the given program.
func dbg_gvar_basetype(program string,
	offset uintptr) (dwarf.Type, error) {
	legolas, err := elf.Open(program)
	if err != nil {
		return nil, fmt.Errorf("error elf.Opening(%s): %v", program, err)
	}
	defer legolas.Close()

	gimli, err := legolas.DWARF()
	if err != nil {
		return nil, fmt.Errorf("no dwarf info for %s? %v", program, err)
	}

	rdr := gimli.Reader()

	for ent, err := rdr.Next(); ent != nil && err != io.EOF; ent, err = rdr.Next() {
		if err != nil {
			return nil, err
		}
		if ent.Tag == dwarf.TagVariable {
			loc, ok := ent.Val(dwarf.AttrLocation).([]uint8)
			// if we can't grab the loc, this is probably a libc symbol, e.g. 'stdin'
			if !ok {
				continue
			}

			if loc[0] != 0x03 { // this isn't a DW_OP_addr, and thus not a global
				continue
			}

			var addr uint64
			buf := bytes.NewReader(loc[1:])
			binary.Read(buf, binary.LittleEndian, &addr)
			if uintptr(addr) == offset {
				ty, err := dbg_base_type(ent)
				if err != nil {
					return nil, err
				}
				if ty.Tag != dwarf.TagBaseType {
					panic("dbg_base_type is buggy")
				}
				typ, err := gimli.Type(ty.Offset)
				if err != nil {
					return nil, err
				}
				return typ, nil
			}
		}
	}

	return nil, fmt.Errorf("offset %v not found", offset)
}

type cdebugvar struct {
	offset string
}

// Looks up the debug information for the variable at the given offset.
func (c cdebugvar) Execute(inferior *ptrace.Tracee) error {
	offset, err := strconv.ParseUint(c.offset, 0, 64)
	if err != nil {
		return fmt.Errorf("cannot convert %v to an offset: %v\n", c.offset, err)
	}

	if err := verify_symbols_loaded(inferior); err != nil {
		return err
	}

	typ, err := dbg_gvar_basetype(globals.program, uintptr(offset))
	if err != nil {
		return err
	}
	fmt.Printf("%v\n", typ)
	return nil
}

// given a type, follows the type chain until it gets to the base type and then
// returns its name.
func dbg_base_type(entry *dwarf.Entry) (*dwarf.Entry, error) {
	bad := &dwarf.Entry{}
	legolas, err := elf.Open(globals.program)
	if err != nil {
		return bad, err
	}
	defer legolas.Close()
	gimli, err := legolas.DWARF()
	if err != nil {
		return bad, err
	}

	atype, ok := entry.Val(dwarf.AttrType).(dwarf.Offset)
	if !ok {
		return bad, fmt.Errorf("bad entry point")
	}
	rdr := gimli.Reader()
	rdr.Seek(atype)
	ent, err := rdr.Next()
	if err != nil {
		return bad, err
	}

	if ent.Tag == dwarf.TagBaseType {
		_, ok := ent.Val(dwarf.AttrName).(string)
		if !ok {
			return bad, fmt.Errorf("name is not a string?")
		}
		return ent, nil
	}
	return dbg_base_type(ent) // recurse.
}

type cdebuginfo struct {
	fqn    string
	offset string
}

func (c cdebuginfo) Execute(inferior *ptrace.Tracee) error {
	// parse 'c.offset' into a usable number instead of a string.
	var offset int64
	if c.offset == "" { // the parameter is optional.
		offset = 0
	} else {
		var err error
		offset, err = strconv.ParseInt(c.offset, 0, 64)
		if err != nil {
			return fmt.Errorf("cannot convert %v to an offset: %v\n", c.offset, err)
		}
	}

	if err := verify_symbols_loaded(inferior); err != nil {
		return err
	}
	sym := symbol(c.fqn, globals.symbols)
	if sym == nil {
		return fmt.Errorf("could not find '%s' among the %d known symbols.",
			c.fqn, len(globals.symbols))
	}

	typ, err := debug.TypeLocal(globals.program, c.fqn, offset)
	if err != nil {
		return err
	}
	fmt.Printf("type: %v\n", typ)

	return nil
}

// identifies the loop bounds for all headers which bound the current location.
type cbounds struct{}

func (cbounds) Execute(inferior *ptrace.Tracee) error {
	symb, err := where(inferior)
	if err != nil {
		return err
	}

	graph := cfg.FromAddress(globals.program, symb.Address())
	if err != nil {
		return err
	}
	if rn := root_node(graph, symb); rn != nil {
		cfg.Analyze(rn)
	}

	bb, err := basic_block(graph, whereis(inferior))
	if err != nil {
		return err
	}
	fmt.Printf("closest bb to 0x%0x is (%s, 0x%0x)\n", whereis(inferior),
		bb.Name, bb.Addr)
	print_bindlist(bb, inferior)

	return nil
}

// identify loop bounds.  assumes we are inside a series of nested loops.  will
// execute the inferior some to identify these loops.
type cboundid struct{}

func (cboundid) Execute(inferior *ptrace.Tracee) error {
	symb, err := where(inferior)
	if err != nil {
		return err
	}

	graph := cfg.FromAddress(globals.program, symb.Address())
	if err != nil {
		return err
	}
	if rn := root_node(graph, symb); rn != nil {
		cfg.Analyze(rn)
	}

	bb, err := basic_block(graph, whereis(inferior))
	if err != nil {
		return err
	}

	dims, err := bind_identify(symb.Name(), bb, inferior)
	if err != nil {
		return err
	}
	if len(dims) == 0 {
		if len(bb.Headers) != 0 {
			panic("broken Headers definition ?")
		}
		return errors.New("not currently in a loop.")
	}
	fmt.Printf("dims: %v\n", dims)
	return nil
}

// reads from memory at the given location and prints it out.
type cread struct {
	location string
}

func (c cread) Execute(inferior *ptrace.Tracee) error {
	ui, err := strconv.ParseUint(c.location, 0, 64)
	if err != nil {
		return err
	}
	address := uintptr(ui)

	word, err := inferior.ReadWord(address)
	if err != nil {
		return err
	}

	fmt.Printf("0x%08x\n", word)
	return nil
}

type chex struct {
	value string
}

func (c chex) Execute(inferior *ptrace.Tracee) error {
	ival, err := strconv.ParseInt(c.value, 0, 64)
	if err != nil {
		return err
	}
	fmt.Printf("0x%0x\n", ival)
	return nil
}

func parse_cmdline(line string) Command {
	tokens := strings.Split(line, " ")
	if len(tokens) == 0 {
		return cparseerror{"no tokens"}
	}
	switch tokens[0] {
	case "cont":
		fallthrough
	case "continue":
		return ccontinue{tokens[1:len(tokens)]}
	case "pid":
		return cpid{}
	case "quit":
		fallthrough
	case "exit":
		return cquit{}
	case "stat":
		fallthrough
	case "status":
		return cstatus{}
	case "stepi":
		fallthrough
	case "step":
		return cstep{}
	case "break":
		return cstop{} // opposite of 'continue' :-)
	case "wait":
		if len(tokens) == 1 {
			return cparseerror{"not enough arguments"}
		}
		return cwait{tokens[1]}
	case "regs":
		fallthrough
	case "registers":
		if len(tokens) == 2 {
			return cregisters{tokens[1]}
		}
		return cregisters{""}
	case "sym":
		fallthrough
	case "symbol":
		if len(tokens) == 1 {
			return cparseerror{"not enough arguments"}
		}
		return csymbol{tokens[1]}
	case "deref":
		if len(tokens) == 1 {
			return cparseerror{"not enough arguments"}
		}
		return cderef{tokens[1]}
	case "cfg":
		if len(tokens) == 1 {
			return ccfg{}
		}
		if len(tokens) == 2 {
			return ccfg{tokens[1]}
		} // 1, optional, parameter.
		return cparseerror{"too many arguments"}
	case "symlist":
		fallthrough
	case "symbols":
		return csymlist{}
	case "whereami":
		return cwhereami{}
	case "decode":
		if len(tokens) != 2 {
			return cparseerror{"not enough arguments"}
		}
		return cdecode{tokens[1]}
	case "bounds":
		return cbounds{}
	case "disassemble":
		return cdisassemble{}
	case "read":
		if len(tokens) == 1 {
			return cparseerror{"not enough arguments"}
		}
		return cread{tokens[1]}
	case "boundid":
		return cboundid{}
	case "debuginfo":
		if len(tokens) == 3 {
			return cdebuginfo{tokens[1], tokens[2]}
		}
		if len(tokens) == 2 {
			return cdebuginfo{tokens[1], ""}
		}
		return cparseerror{"invalid # of arguments."}
	case "debugvar":
		if len(tokens) == 2 {
			return cdebugvar{tokens[1]}
		}
		return cparseerror{"not enough arguments"}
	case "hex":
		if len(tokens) == 2 {
			return chex{tokens[1]}
		}
		return cparseerror{"not enough arguments"}
	default:
		return cgeneric{tokens}
	}
}
func Commands() chan Command {
	cmds := make(chan Command)
	go func() {
		defer close(cmds)
		rdr := bufio.NewReader(os.Stdin)
		for {
			<-cmds // wait for 'green light' from our parent.
			fmt.Printf("> ")
			os.Stdout.Sync()
			s, err := rdr.ReadString('\n')
			if err != nil {
				fmt.Fprintf(os.Stderr, "error scanning line: %v\n", err)
				cmds <- nil // signal EOF.
				return
			}
			cmd := parse_cmdline(strings.TrimSpace(s))
			cmds <- cmd
		}
	}()
	return cmds
}
