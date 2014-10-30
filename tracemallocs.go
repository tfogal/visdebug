package main

import(
  "fmt"
  "io"
  "log"
)

func newmallocs(argv []string) {
  inferior, err := instrument(argv)
  if err != nil {
    log.Fatalf("error: %v\n", err)
  }
  defer inferior.Close()

  var mt MallocTrace
  mt.Setup(inferior)
  for {
    ievent, err := ihandle(inferior)
    if err == io.EOF {
      break
    } else if err != nil {
      log.Fatalf("running %s: %v\n", argv[0], err)
    }
    switch iev := ievent.(type) {
    case trap:
      if err := ie.Trap(inferior, iev.iptr) ; err != nil {
        log.Fatalf("error trapping 0x%x: %v\n", iev.iptr, err)
      }
    case segfault:
      if err := ie.Segfault(inferior, iev.addr) ; err != nil {
        log.Fatalf("error in segfault@0x%x handling: %v\n", iev.addr, err)
      }
    default:
      log.Fatalf("unexpected event: %v\n", iev)
    }
  }
  fmt.Printf("[sup] %s exited normally.\n", argv[0])
}
