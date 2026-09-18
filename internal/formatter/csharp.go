package formatter

import (
	"fmt"
	"strings"
)

var _ Formatter = (*Csharp)(nil)

type Csharp struct{}

func NewCsharp() (*Csharp, error) {
	return &Csharp{}, nil
}

func (c *Csharp) Generate(ciphertext []byte, key []byte, nonce []byte) string {
	var sb strings.Builder

	const byteFormat = "0x%02x"
	const seperator = ","
	const perLine = 15
	const newLine = "\n"

	fmt.Fprintf(&sb, "byte[] shellcode = new byte[%d] = {\n%s\n};\n", len(ciphertext), formatBytes(ciphertext, perLine, byteFormat, seperator, newLine))
	fmt.Fprintf(&sb, "byte[] key = new byte[%d] = {\n%s\n};\n", len(key), formatBytes(key, perLine, byteFormat, seperator, newLine))
	if len(nonce) != 0 {
		fmt.Fprintf(&sb, "byte[] nonce = new byte[%d] = {\n%s\n};\n", len(nonce), formatBytes(nonce, perLine, byteFormat, seperator, newLine))
	}

	return sb.String()
}
