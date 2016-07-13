/* Distributed under the MIT license.  See the LICENSE file.
 * Copyright (c) 2014--2016 Thomas Fogal */
package cfg

import "testing"

func lassert(t *testing.T, conditional bool, msg string) {
	if !conditional {
		t.Fatalf("%s\n", msg)
		t.FailNow()
	}
}

func TestSingleNodeLoop(t *testing.T) {
	n := makeNode("root", 0x00000042)
	Analyze(n)
	lassert(t, n.Depth() == 0, "single node is not a loop!")
}

func TestLoopWithExit(t *testing.T) {
	entry := makeNode("entry", 0x00000024)
	ltest := makeNode("test", 0x00000042)
	body := makeNode("body", 0x00000084)
	done := makeNode("done", 0x00000096)
	entry.Edgelist = make([]*Edge, 1)
	ltest.Edgelist = make([]*Edge, 2)
	body.Edgelist = make([]*Edge, 1)
	// no exit from 'done', so no edges.
	entry.Edgelist[0] = &Edge{ltest, 0}
	ltest.Edgelist[0] = &Edge{body, 0}
	ltest.Edgelist[1] = &Edge{done, 0}
	body.Edgelist[0] = &Edge{ltest, 0}

	Analyze(entry)
	lassert(t, ltest.LoopHeader(), "loop test is a loop header")
	lassert(t, body.Depth() == 1, "body is in the loop")
	lassert(t, done.LoopHeader() == false, "exit block is not a loop header")
	lassert(t, done.Depth() == 0, "exit block is not in a loop")
}
