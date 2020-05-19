package certificate_searcher

func base128IntLength(n int64) int {
	if n == 0 {
		return 1
	}

	l := 0
	for i := n; i > 0; i >>= 7 {
		l++
	}

	return l
}

func appendBase128Int(dst []byte, n int64) []byte {
	l := base128IntLength(n)

	for i := l - 1; i >= 0; i-- {
		o := byte(n >> uint(i*7))
		o &= 0x7f
		if i != 0 {
			o |= 0x80
		}

		dst = append(dst, o)
	}

	return dst
}

func lengthLength(i int) (numBytes int) {
	numBytes = 1
	for i > 255 {
		numBytes++
		i >>= 8
	}
	return
}

func appendLength(dst []byte, i int) []byte {
	n := lengthLength(i)

	for ; n > 0; n-- {
		dst = append(dst, byte(i>>uint((n-1)*8)))
	}

	return dst
}

func marshalTagAndLength(t tagAndLength) []byte {
	dst := make([]byte, 0)
	b := uint8(t.class) << 6
	if t.isCompound {
		b |= 0x20
	}
	if t.tag >= 31 {
		b |= 0x1f
		dst = append(dst, b)
		dst = appendBase128Int(dst, int64(t.tag))
	} else {
		b |= uint8(t.tag)
		dst = append(dst, b)
	}

	if t.length >= 128 {
		l := lengthLength(t.length)
		dst = append(dst, 0x80|byte(l))
		dst = appendLength(dst, t.length)
	} else {
		dst = append(dst, byte(t.length))
	}

	return dst
}
