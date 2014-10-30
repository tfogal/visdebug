package main

import(
  "fmt"
  "io"
  "./msg"
)

var evc = msg.StdChan()

func newmallocs(argv []string, ie InferiorEvent) {
  inferior, err := instrument(argv)
  if err != nil {
    evc.Error("err starting program: %v\n", err)
  }
  defer inferior.Close()

  ie.Setup(inferior)
  defer ie.Close(inferior)

  for {
    ievent, err := ihandle(inferior)
    if err == io.EOF {
      break
    } else if err != nil {
      evc.Error("running %s: %v\n", argv[0], err)
    }
    switch iev := ievent.(type) {
    case trap:
      if err := ie.Trap(inferior, iev.iptr) ; err != nil {
        evc.Error("error trapping 0x%x: %v\n", iev.iptr, err)
      }
    case segfault:
      if err := ie.Segfault(inferior, iev.addr) ; err != nil {
        evc.Error("%v\n", err)
      }
    default:
      evc.Error("unexpected event: %v\n", iev)
    }
  }
  fmt.Printf("[sup] %s exited normally.\n", argv[0])
}
