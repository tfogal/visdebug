package cfg

import "testing"

func TestDepthSimple(t *testing.T) {
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
	if entry.Depth() != 0 {
		t.Error("entry depth is not 1:", entry.Depth())
	}
	if hdr.Depth() != 0 {
		t.Error("header depth is not 1:", hdr.Depth())
	}
	if body.Depth() != 1 {
		t.Error("body depth is not 1:", body.Depth())
	}
	if out.Depth() != 0 {
		t.Error("out node depth is not 1:", out.Depth())
	}
}

type tstdepth struct {
	nodename string
	depth    uint
}

var depth_test = /* hah! */ []tstdepth{
	{"smooth2", 0},
	{"4008e8", 0},
	{"4007fc", 1},
	{"4008fd", 0},
	{"400b20", 0},
	{"40090a", 1},
	{"400b06", 1},
	{"400b1b", 1},
	{"400917", 2},
	{"400b35", 0},
}

func TestDepthSmooth2(t *testing.T) {
	entry := smooth2()
	Analyze(entry)

	for _, tst := range depth_test {
		n := findnode(entry, tst.nodename)
		if n.Depth() != tst.depth {
			t.Error("node", n.Name, "(", n.Addr, ") should have depth", tst.depth,
				"but has:", n.Depth())
		}
	}
}
