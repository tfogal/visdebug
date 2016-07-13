/* Distributed under the MIT license.  See the LICENSE file.
 * Copyright (c) 2014--2016 Thomas Fogal */
package debug

import "testing"

type slebtest struct {
	input  []uint8
	output int64
}

func TestSlebConv(t *testing.T) {
	slebtests := []slebtest{
		{[]uint8{2}, 2},
		{[]uint8{0x7e}, -2},
		{[]uint8{127 + 0x80, 0}, 127},
		{[]uint8{1 + 0x80, 0x7f}, -127},
		{[]uint8{0 + 0x80, 1}, 128},
		{[]uint8{0 + 0x80, 0x7f}, -128},
		{[]uint8{1 + 0x80, 1}, 129},
		{[]uint8{0x7f + 0x80, 0x7e}, -129},
	}
	for _, tst := range slebtests {
		v := sleb128(tst.input)
		if v != tst.output {
			t.Fatalf("%v -> %v, not %v!", tst.input, tst.output, v)
		}
	}
}
