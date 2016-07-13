/* Distributed under the MIT license.  See the LICENSE file.
 * Copyright (c) 2014--2016 Thomas Fogal */
package main

import (
	"./msg"
	"io"
)

var evc = msg.StdChan("evc")

func supervise(argv []string, ie InferiorEvent) {
	inferior, err := instrument(argv)
	if err != nil {
		evc.Error("err starting program: %v\n", err)
		return
	}
	defer inferior.Close()

	if err := ie.Setup(inferior); err != nil {
		evc.Error("Could not initialize event handler: %v", err)
		return
	}
	defer ie.Close(inferior)

	for {
		ievent, err := ihandle(inferior)
		if err == io.EOF {
			break
		} else if err != nil {
			evc.Error("running %s: %v\n", argv[0], err)
			return
		}
		switch iev := ievent.(type) {
		case trap:
			if err := ie.Trap(inferior, iev.iptr); err != nil {
				evc.Error("error trapping 0x%x: %v\n", iev.iptr, err)
				return
			}
		case segfault:
			if err := ie.Segfault(inferior, iev.addr); err != nil {
				evc.Error("segfault error: %v\n", err)
				return
			}
		default:
			evc.Error("unexpected event: %v\n", iev)
			return
		}
	}
	evc.Printf("%s exited normally.\n", argv[0])
}
