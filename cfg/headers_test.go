package cfg

import "testing"

func TestHeadersSimple(t *testing.T) {
	entry := makeNode("entry", 0x400b0a)
	hdr := makeNode("hdr", 0x400c0a)
	out := makeNode("out", 0x400d0a)
	body := makeNode("body", 0x400ead)
	entry.Edgelist = make([]*Edge, 1)
	entry.Edgelist[0] = &Edge{hdr, 0}
	hdr.Edgelist = make([]*Edge, 2)
	hdr.Edgelist[0] = &Edge{out, 0}
	hdr.Edgelist[1] = &Edge{body, 0}
	body.Edgelist = make([]*Edge, 1)
	body.Edgelist[0] = &Edge{hdr, 0}

	Analyze(entry)
	if entry.LoopHeader() {
		t.Error("entry node incorrectly marked as a loop header")
	}
	if !hdr.LoopHeader() {
		t.Error("did not correctly find / identify loop header")
	}
	if body.LoopHeader() {
		t.Error("marked the loop body as a loop header")
	}
	if out.LoopHeader() {
		t.Error("marked the exit node as a loop header")
	}
}

func TestHeadersSmooth2(t *testing.T) {
	entry := smooth2()
	Analyze(entry)
	if !findnode(entry, "400b20").LoopHeader() {
		t.Error("400b20")
	}
	if !findnode(entry, "400b06").LoopHeader() {
		t.Error("400b06")
	}
}
