package formatter

import (
	"fmt"
	"strings"
)

var _ Formatter = (*Nim)(nil)

type Nim struct{}

func NewNim() (*Nim, error) {
	return &Nim{}, nil
}

func (c *Nim) Generate(ciphertext []byte, key []byte, nonce []byte) string {
	var sb strings.Builder

	const byteFormat = "0x%02x"
	const seperator = ","
	const perLine = 15
	const newLine = "\n"

	fmt.Fprintf(&sb, "var shellcode: array[%d, byte] = [\nbyte %s\n]\n", len(ciphertext), formatBytes(ciphertext, perLine, byteFormat, seperator, newLine))
	fmt.Fprintf(&sb, "var key: array[%d, byte] = [\nbyte %s\n]\n", len(key), formatBytes(key, perLine, byteFormat, seperator, newLine))
	if len(nonce) != 0 {
		fmt.Fprintf(&sb, "var nonce: array[%d, byte] = [\nbyte %s\n]\n", len(nonce), formatBytes(nonce, perLine, byteFormat, seperator, newLine))
	}

	return sb.String()
}
