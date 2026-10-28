package evidence

import (
	"net"
	"strings"
	"unicode"
)

// IsValidDomain reports whether name is a valid ASCII DNS hostname.
func IsValidDomain(name string) bool {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil {
		return false
	}

	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
				return false
			}
			if r > unicode.MaxASCII {
				return false
			}
		}
	}

	return true
}
