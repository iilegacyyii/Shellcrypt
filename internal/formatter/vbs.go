package formatter

import (
	"fmt"
	"strings"
)

var _ Formatter = (*VBS)(nil)

type VBS struct{}

func NewVBS() (*VBS, error) {
	return &VBS{}, nil
}

func (a *VBS) Generate(ciphertext []byte, key []byte, nonce []byte) string {
	var sb strings.Builder

	const byteFormat = "Chr(%d)"
	const seperator = "&"
	const newLine = "\n"

	fmt.Fprintf(&sb, "shellcode=%s\n", formatBytes(ciphertext, len(ciphertext), byteFormat, seperator, newLine))
	fmt.Fprintf(&sb, "key=%s\n", formatBytes(key, len(key), byteFormat, seperator, newLine))
	if len(nonce) != 0 {
		fmt.Fprintf(&sb, "nonce=%s\n", formatBytes(nonce, len(nonce), byteFormat, seperator, newLine))
	}

	return sb.String()
}
