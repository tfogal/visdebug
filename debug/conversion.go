package debug

// converts a signed "LEB128" from a byte array into a signed integer.
// algorithm is modified from the dwarf v4 spec.
func sleb128(leb []uint8) int64 {
	result := uint64(0) // go forces unsigned for shifting.  cast later.  sigh.
	shift := uint(0)
	const nbits = 64
	for b := range leb {
		// 0x91 seems to indicate 'this is a multi-byte thing' as opposed to
		// actually being used.  Not 100% sure this is correct, but we match
		// objdump on some test code with this continue.
		if leb[b] == 0x91 {
			continue
		}
		value := leb[b] & 0x7f
		result |= uint64(value) << uint64(shift)
		shift += 7
		// the DWARF algorithm reads the high-order bit as a sentinel, but instead
		// of an infinite array the Go API just gives us a correctly-sized slice.
	}
	// highest-order bit is the sentinel, so second highest is the sign.
	if shift < nbits && (leb[len(leb)-1]&0x40) != 0 {
		result = result | uint64(int64(-1)<<shift) // sign extension.
	}
	return int64(result)
}
