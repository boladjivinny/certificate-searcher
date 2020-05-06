package certificate_searcher

var asciiLowerValidHostnameChars = map[rune]struct{}{
	'a': {},
	'b': {},
	'c': {},
	'd': {},
	'e': {},
	'f': {},
	'g': {},
	'h': {},
	'i': {},
	'j': {},
	'k': {},
	'l': {},
	'm': {},
	'n': {},
	'o': {},
	'p': {},
	'q': {},
	'r': {},
	's': {},
	't': {},
	'u': {},
	'v': {},
	'w': {},
	'y': {},
	'z': {},
	'0': {},
	'1': {},
	'2': {},
	'3': {},
	'4': {},
	'5': {},
	'6': {},
	'7': {},
	'8': {},
	'9': {},
	'.': {},
	'-': {},
}



func ValidHostname(s string) bool {
	hostnameRunes := []rune(s)
	for _, r := range hostnameRunes {
		if _, present := asciiLowerValidHostnameChars[r]; !present {
			return false
		}
	}
	return true
}