package formatter

import (
	"fmt"
	"strings"
)

var _ Formatter = (*Powershell)(nil)

type Powershell struct{}

func NewPowershell() (*Powershell, error) {
	return &Powershell{}, nil
}

func (r *Powershell) Generate(ciphertext []byte, key []byte, nonce []byte) string {
	var sb strings.Builder

	const byteFormat = "0x%02x"
	const seperator = ","
	const newLine = "\n"

	fmt.Fprintf(&sb, "[Byte[]] shellcode = %s\n", formatBytes(ciphertext, len(ciphertext), byteFormat, seperator, newLine))
	fmt.Fprintf(&sb, "[Byte[]] key = %s\n", formatBytes(key, len(key), byteFormat, seperator, newLine))
	if len(nonce) != 0 {
		fmt.Fprintf(&sb, "[Byte[]] nonce = %s\n", formatBytes(nonce, len(nonce), byteFormat, seperator, newLine))
	}

	return sb.String()
}
