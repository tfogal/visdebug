package cfg

import "testing"

type testdominfo struct {
	nodename  string
	dominance map[uintptr]bool
}

var domtests = []testdominfo{
	{"smooth2", map[uintptr]bool{0x4007e7: true}},
	{"4008e8", map[uintptr]bool{0x4007e7: true, 0x4008e8: true}},
	{"4007fc", map[uintptr]bool{0x4007e7: true, 0x4008e8: true, 0x4007fc: true}},
	{"4008fd", map[uintptr]bool{0x4007e7: true, 0x4008e8: true, 0x4008fd: true}},
	{"4007fc", map[uintptr]bool{0x4007e7: true, 0x4008e8: true, 0x4007fc: true}},
	{"400b20", map[uintptr]bool{0x4007e7: true, 0x4008e8: true, 0x4008fd: true,
		0x400b20: true}},
	{"400b35", map[uintptr]bool{0x4007e7: true, 0x4008e8: true, 0x4008fd: true,
		0x400b20: true, 0x400b35: true}},
	{"40090a", map[uintptr]bool{0x4007e7: true, 0x4008e8: true, 0x4008fd: true,
		0x400b20: true, 0x40090a: true}},
	{"400b06", map[uintptr]bool{0x4007e7: true, 0x4008e8: true, 0x4008fd: true,
		0x400b20: true, 0x40090a: true, 0x400b06: true}},
	{"400b1b", map[uintptr]bool{0x4007e7: true, 0x4008e8: true, 0x4008fd: true,
		0x400b20: true, 0x40090a: true, 0x400b06: true,
		0x400b1b: true}},
	{"400917", map[uintptr]bool{0x4007e7: true, 0x4008e8: true, 0x4008fd: true,
		0x400b20: true, 0x40090a: true, 0x400b06: true,
		0x400917: true}},
}

func TestDominance(t *testing.T) {
	entry := smooth2()
	dominance(entry)

	for _, tst := range domtests {
		node := findnode(entry, tst.nodename)
		dset := domset{tst.dominance}
		if !sameset(node.dominators, dset) {
			t.Error("For", tst, "expected:", tst.dominance, "got", node.dominators)
		}
	}
}
