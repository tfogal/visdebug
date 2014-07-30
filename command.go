// Houses the commands we use in our interactive debugging mode.
package main

import "bufio"
import "errors"
import "fmt"
import "os"
import "syscall"
import "strconv"
import "strings"
import "github.com/tfogal/ptrace"
import "./bfd"
import "./debug"

type CmdGlobal struct {
  program string
}

// the list of symbols from the process, might be nil.
var symbols []bfd.Symbol
// initialization info that commands might want to use.
var globals CmdGlobal

func verify_symbols_loaded(inferior *ptrace.Tracee) error {
  if symbols == nil {
    var err error // so we can use "=" and ensure 'symbols' is the global.
    symbols, err = bfd.SymbolsProcess(inferior)
    if err != nil { return err }
  }
  return nil
}

type Command interface{
  Execute(*ptrace.Tracee) (error)
}

type cgeneric struct {
  args []string
}
func (c cgeneric) Execute(proc *ptrace.Tracee) (error) {
  fmt.Printf("unknown cmd: %s\n", c.args)
  return nil
}

type ccontinue struct {
  args []string
}
func (c ccontinue) Execute(proc *ptrace.Tracee) (error) {
  fmt.Printf("continuing ... %v\n", c.args)
  err := proc.Continue()
  return err
}

type cstep struct{} // needs no args.
func (c cstep) Execute(proc *ptrace.Tracee) (error) {
  err := proc.SingleStep()
  return err
}

type cstop struct{}
func (c cstop) Execute(proc *ptrace.Tracee) (error) {
  err := proc.SendSignal(syscall.SIGSTOP)
  return err
}

type cpid struct{}
func (c cpid) Execute(proc *ptrace.Tracee) (error) {
  fmt.Printf("%d\n", proc.PID())
  return nil
}

type cstatus struct{}
func (c cstatus) Execute(proc *ptrace.Tracee) (error) {
  fn := fmt.Sprintf("/proc/%d/stat", proc.PID())
  file, err := os.Open(fn)
  if err != nil { return err }
  defer file.Close()
  var pid int
  var name string
  var state rune
  n, err := fmt.Fscanf(file, "%d %s %c", &pid, &name, &state)
  if err != nil { return err }
  if n <= 1 {
    return errors.New("could not scan enough")
  }
  fmt.Printf("process %d is ", proc.PID())
  switch(state) {
    case 'D': fmt.Printf("in uninterruptible sleep (io?)\n"); break
    case 'R': fmt.Printf("running\n"); break
    case 'S': fmt.Printf("sleeping\n"); break
    case 't': fmt.Printf("stopped (tracing)\n"); break
    case 'W': fmt.Printf("(impossibly) paging\n"); break
    case 'X': fmt.Printf("(impossibly) dead\n"); break
    case 'Z': fmt.Printf("awaiting reaping.\n"); break
    default: fmt.Printf("unknown?!\n"); break
  }
  return nil
}

type cquit struct{}
func (c cquit) Execute(proc *ptrace.Tracee) (error) {
  if err := proc.SendSignal(syscall.SIGKILL) ; err != nil {
    return err
  }
  return nil
}

type cwait struct{
  funcname string
}
func (c cwait) Execute(inferior *ptrace.Tracee) (error) {
  if err := verify_symbols_loaded(inferior) ; err != nil {
    return err
  }
  sym := symbol(c.funcname, symbols) // symbol lookup
  if sym == nil {
    return fmt.Errorf("could not find '%s' among the %d known symbols.\n",
                      c.funcname, len(symbols))
  }
  debug.WaitUntil(inferior, sym.Address())
  fmt.Printf("Hit BP!\n")
  return nil
}

type cparseerror struct{
  reason string
}
func (c cparseerror) Execute(*ptrace.Tracee) (error) {
  return fmt.Errorf("parse error: %s", c.reason)
}

type cregisters struct{}
func (cregisters) Execute(inferior *ptrace.Tracee) (error) {
  regs, err := inferior.GetRegs()
  if err != nil { return err }

  wd, err := inferior.ReadWord(uintptr(regs.Rip))
  if err != nil { return err }

  fmt.Printf("%9s %14s %14s %13s %21s\n", "iptr", "RAX", "RBP", "RSP",
             "next-opcode")
  fmt.Printf("0x%012x 0x%012x 0x%012x 0x%012x 0x%012x\n", regs.Rip, regs.Rax,
             regs.Rbp, regs.Rsp, wd)
  return nil
}

type csymbol struct{
  symname string
}
func (c csymbol) Execute(inferior *ptrace.Tracee) (error) {
  if err := verify_symbols_loaded(inferior) ; err != nil {
    return err
  }
  sym := symbol(c.symname, symbols) // symbol lookup
  if sym == nil {
    return fmt.Errorf("could not find '%s' among the %d known symbols.\n",
                      c.symname, len(symbols))
  }
  fmt.Printf("'%s' is at 0x%012x\n", sym.Name(), sym.Address())
  return nil
}

type cderef struct {
  addr string // really, a uintptr, but do the parsing in the command.
}
func (c cderef) Execute(inferior *ptrace.Tracee) (error) {
  if c.addr == "" {
    return errors.New("empty address given")
  }
  ui, err := strconv.ParseUint(c.addr, 0, 64)
  if err != nil { return err }
  address := uintptr(ui)

  fmt.Printf("addr: 0x%0x\n", address)

  word, err := inferior.ReadWord(address)
  if err != nil { return err }

  fmt.Printf("0x%0x\n", word)
  return nil
}

func parse_cmdline(line string) (Command) {
  tokens := strings.Split(line, " ")
  if len(tokens) == 0 { return cparseerror{"no tokens"} }
  switch(tokens[0]) {
    case "cont": fallthrough
    case "continue": return ccontinue{tokens[1:len(tokens)]}
    case "pid": return cpid{}
    case "quit": fallthrough
    case "exit": return cquit{}
    case "stat": fallthrough
    case "status": return cstatus{}
    case "stepi": fallthrough
    case "step": return cstep{}
    case "break": return cstop{} // opposite of 'continue' :-)
    case "wait":
      if len(tokens) == 1 { return cparseerror{"not enough arguments"} }
      return cwait{tokens[1]}
    case "regs": fallthrough
    case "registers": return cregisters{}
    case "sym": fallthrough
    case "symbol":
      if len(tokens) == 1 { return cparseerror{"not enough arguments"} }
      return csymbol{tokens[1]}
    case "deref":
      if len(tokens) == 1 { return cparseerror{"not enough arguments"} }
      return cderef{tokens[1]}
    default: return cgeneric{tokens}
  }
}
func Commands(gbl CmdGlobal) (chan Command) {
  globals = gbl
  cmds := make(chan Command)
  go func() {
    defer close(cmds)
    rdr := bufio.NewReader(os.Stdin)
    for {
      <- cmds // wait for 'green light' from our parent.
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
