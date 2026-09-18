package formatter

import (
	"fmt"
	"strings"
)

var _ Formatter = (*Go)(nil)

type Go struct{}

func NewGo() (*Go, error) {
	return &Go{}, nil
}

func (r *Go) Generate(ciphertext []byte, key []byte, nonce []byte) string {
	var sb strings.Builder

	const byteFormat = "0x%02x"
	const seperator = ","
	const perLine = 15
	const newLine = "\n"

	fmt.Fprintf(&sb, "shellcode := []byte {\n%s\n}\n", formatBytes(ciphertext, perLine, byteFormat, seperator, newLine))
	fmt.Fprintf(&sb, "key := []byte {\n%s\n}\n", formatBytes(key, perLine, byteFormat, seperator, newLine))
	if len(nonce) != 0 {
		fmt.Fprintf(&sb, "nonce := []byte {\n%s\n}\n", formatBytes(nonce, perLine, byteFormat, seperator, newLine))
	}

	return sb.String()
}
