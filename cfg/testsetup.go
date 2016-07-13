/* Distributed under the MIT license.  See the LICENSE file.
 * Copyright (c) 2014--2016 Thomas Fogal */
package cfg

/* 'smooth2' is a (sub)graph copied from a real program which performs a 2d
 * smoothing operation.  there is a 1D loop that primes the top boundary.
 * the smoothing is broken in that it doesn't handle the side and bottom
 * boundaries (which would create 3 more 1D loops), but it is fine for a test
 * program. */
func smooth2() *Node {
	entry := makeNode("smooth2", 0x4007e7) // also 4007e7, FWIW.
	n4008e8 := makeNode("4008e8", 0x4008e8)
	n4007fc := makeNode("4007fc", 0x4007fc)
	n4008fd := makeNode("4008fd", 0x4008fd)
	n400b20 := makeNode("400b20", 0x400b20)
	n40090a := makeNode("40090a", 0x40090a)
	n400b35 := makeNode("400b35", 0x400b35)
	n400b06 := makeNode("400b06", 0x400b06)
	n400b1b := makeNode("400b1b", 0x400b1b)
	n400917 := makeNode("400917", 0x400917)

	entry.Edgelist = make([]*Edge, 1)
	entry.Edgelist[0] = &Edge{n4008e8, 0}
	n4008e8.Edgelist = make([]*Edge, 2)
	n4008e8.Edgelist[0] = &Edge{n4007fc, 0}
	n4008e8.Edgelist[1] = &Edge{n4008fd, 0}
	n4007fc.Edgelist = make([]*Edge, 1)
	n4007fc.Edgelist[0] = &Edge{n4008e8, 0}
	n4008fd.Edgelist = make([]*Edge, 1)
	n4008fd.Edgelist[0] = &Edge{n400b20, 0}
	n400b20.Edgelist = make([]*Edge, 2)
	n400b20.Edgelist[0] = &Edge{n40090a, 0}
	n400b20.Edgelist[1] = &Edge{n400b35, 0}
	n40090a.Edgelist = make([]*Edge, 1)
	n40090a.Edgelist[0] = &Edge{n400b06, 0}
	n400b06.Edgelist = make([]*Edge, 2)
	n400b06.Edgelist[0] = &Edge{n400b1b, 0}
	n400b06.Edgelist[1] = &Edge{n400917, 0}
	n400b1b.Edgelist = make([]*Edge, 1)
	n400b1b.Edgelist[0] = &Edge{n400b20, 0}
	n400917.Edgelist = make([]*Edge, 1)
	n400917.Edgelist[0] = &Edge{n400b06, 0}

	return entry
}

func findnode(from *Node, name string) *Node {
	sn := make(map[uintptr]bool)
	retval := findnode_h(from, name, sn)
	if retval == nil {
		panic("node was not found, test is broken.")
	}
	return retval
}
func findnode_h(srch *Node, name string, seen map[uintptr]bool) *Node {
	if seen[srch.Addr] {
		return nil
	}
	seen[srch.Addr] = true
	if srch.Name == name {
		return srch
	}
	for _, edge := range srch.Edgelist {
		n := findnode_h(edge.To, name, seen)
		if n != nil {
			return n
		}
	}
	return nil
}
