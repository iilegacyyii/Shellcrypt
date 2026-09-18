package formatter

import (
	"fmt"
	"strings"
)

var _ Formatter = (*VBA)(nil)

type VBA struct{}

func NewVBA() (*VBA, error) {
	return &VBA{}, nil
}

func (v *VBA) Generate(ciphertext []byte, key []byte, nonce []byte) string {
	var sb strings.Builder

	const byteFormat = "%d"
	const seperator = ","
	const perLine = 15
	const newLine = "_\n"

	fmt.Fprintf(&sb, "shellcode = Array(%s)\n", formatBytes(ciphertext, perLine, byteFormat, seperator, newLine))
	fmt.Fprintf(&sb, "key = Array(%s)\n", formatBytes(key, perLine, byteFormat, seperator, newLine))
	if len(nonce) != 0 {
		fmt.Fprintf(&sb, "nonce = Array(%s)\n", formatBytes(nonce, perLine, byteFormat, seperator, newLine))
	}

	return sb.String()
}
