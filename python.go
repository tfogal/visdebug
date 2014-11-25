/* This defines an InferiorEvent implementation that just forwards the arrays
 * it gets to python and runs a user-provided script. */
package main

import(
  "./msg"
  "github.com/sbinet/go-python"
  "github.com/tfogal/ptrace"
)

type Python struct {
  BaseEvent
}

var pyc = msg.StdChan()

func (p *Python) Setup(inferior *ptrace.Tracee) error {
  if err := p.BaseEvent.Setup(inferior) ; err != nil {
    return err
  }

  if err := python.Initialize() ; err != nil {
    return err
  }

  pyc.Trace("Initialized.\n")

  return nil
}

func (p *Python) Close(inferior *ptrace.Tracee) error {
  if err := python.Finalize() ; err != nil {
    return err
  }

  pyc.Trace("Finalized.\n")
  return nil
}
