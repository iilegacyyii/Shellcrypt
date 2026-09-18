package formatter

import (
	"fmt"
	"strings"
)

var _ Formatter = (*Rust)(nil)

type Rust struct{}

func NewRust() (*Rust, error) {
	return &Rust{}, nil
}

func (r *Rust) Generate(ciphertext []byte, key []byte, nonce []byte) string {
	var sb strings.Builder

	const byteFormat = "0x%02x"
	const seperator = ","
	const perLine = 15
	const newLine = "\n"

	fmt.Fprintf(&sb, "let shellcode: [u8; %d] = [\n%s\n];\n", len(ciphertext), formatBytes(ciphertext, perLine, byteFormat, seperator, newLine))
	fmt.Fprintf(&sb, "let key: [u8; %d] = [\n%s\n];\n", len(key), formatBytes(key, perLine, byteFormat, seperator, newLine))
	if len(nonce) != 0 {
		fmt.Fprintf(&sb, "let nonce: [u8; %d] = [\n%s\n];\n", len(nonce), formatBytes(nonce, perLine, byteFormat, seperator, newLine))
	}

	return sb.String()
}
