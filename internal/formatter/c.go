package formatter

import (
	"fmt"
	"strings"
)

var _ Formatter = (*C)(nil)

type C struct{}

func NewC() (*C, error) {
	return &C{}, nil
}

func (c *C) Generate(ciphertext []byte, key []byte, nonce []byte) string {
	var sb strings.Builder

	const byteFormat = "0x%02x"
	const seperator = ","
	const perLine = 15
	const newLine = "\n"

	fmt.Fprintf(&sb, "unsigned char shellcode[%d] = {\n%s\n};\n", len(ciphertext), formatBytes(ciphertext, perLine, byteFormat, seperator, newLine))
	fmt.Fprintf(&sb, "unsigned char key[%d] = {\n%s\n};\n", len(key), formatBytes(key, perLine, byteFormat, seperator, newLine))
	if len(nonce) != 0 {
		fmt.Fprintf(&sb, "unsigned char nonce[%d] = {\n%s\n};\n", len(nonce), formatBytes(nonce, perLine, byteFormat, seperator, newLine))
	}

	return sb.String()
}
