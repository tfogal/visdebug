/* This defines an InferiorEvent implementation that just forwards the arrays
 * it gets to python and runs a user-provided script. */
package main

import(
  "errors"
  "unsafe"
  "./msg"
  "github.com/sbinet/go-python"
  "github.com/tfogal/ptrace"
  "github.com/tfogal/gonpy"
)

type Python struct {
  BaseEvent
  module *python.PyObject
  dict *python.PyObject
  data *python.PyObject
}

var pyc = msg.StdChan()

func (p *Python) Setup(inferior *ptrace.Tracee) error {
  if err := p.BaseEvent.Setup(inferior) ; err != nil {
    return err
  }

  if err := python.Initialize() ; err != nil {
    return err
  }

  var err error
  p.module, err = python.Py_InitModule("simulation")
  if err != nil {
    return err
  }

  p.dict = python.PyModule_GetDict(p.module)
  if p.dict == nil {
    return errors.New("newly-created module has no dict?")
  }

  if i := python.PyRun_SimpleString("import simulation") ; i != 0 {
    return errors.New("could not import module we created")
  }
  if i := python.PyRun_SimpleString("import numpy") ; i != 0 {
    return errors.New("could not import numpy.")
  }

  gonpy.Import()

  // just hacks to test out if it works
  dims := []int{2,2,4}
  buf := make([]float32, 16)
  buf[0] = 42.424242
  p.data, err = gonpy.Array_SimpleNewFromData(uint(len(dims)), dims,
                                              gonpy.NPY_FLOAT,
                                              unsafe.Pointer(&buf[0]))
  if err != nil {
    return err
  }
  str := python.PyString_FromString("testing")
  python.PyDict_SetItem(p.dict, str, p.data)
  str.Clear()

  if err := python.PyRun_SimpleFile("test.py") ; err != nil {
    return err
  }

  pyc.Trace("Initialized.\n")

  return nil
}

func (p *Python) Close(inferior *ptrace.Tracee) error {
  python.PyDict_Clear(p.dict)
  p.dict.Clear()
  p.module.Clear()
  p.pydata.Clear()
  p.dict = nil
  p.module = nil
  p.pydata = nil

  if err := python.Finalize() ; err != nil {
    return err
  }

  pyc.Trace("Finalized.\n")
  return nil
}
