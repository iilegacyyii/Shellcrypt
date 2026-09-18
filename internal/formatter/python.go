package formatter

import (
	"fmt"
	"strings"
)

var _ Formatter = (*Python)(nil)

type Python struct{}

func NewPython() (*Python, error) {
	return &Python{}, nil
}

func (r *Python) Generate(ciphertext []byte, key []byte, nonce []byte) string {
	var sb strings.Builder

	const byteFormat = "\\x%02x"
	const seperator = ""
	const newLine = "\n"

	fmt.Fprintf(&sb, "shellcode = b\"%s\"\n", formatBytes(ciphertext, len(ciphertext), byteFormat, seperator, newLine))
	fmt.Fprintf(&sb, "key = b\"%s\"\n", formatBytes(key, len(key), byteFormat, seperator, newLine))
	if len(nonce) != 0 {
		fmt.Fprintf(&sb, "nonce = b\"%s\"\n", formatBytes(nonce, len(nonce), byteFormat, seperator, newLine))
	}

	return sb.String()
}
