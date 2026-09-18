package formatter

import (
	"fmt"
	"sort"
	"strings"
)

type Formatter interface {
	Generate(ciphertext []byte, key []byte, nonce []byte) string
}

type factory func() (Formatter, error)

var formats = map[string]factory{
	"c":      func() (Formatter, error) { return NewC() },
	"rust":   func() (Formatter, error) { return NewRust() },
	"csharp": func() (Formatter, error) { return NewCsharp() },
	"go":     func() (Formatter, error) { return NewGo() },
	"nim":    func() (Formatter, error) { return NewNim() },
	"ps1":    func() (Formatter, error) { return NewPowershell() },
	"python": func() (Formatter, error) { return NewPython() },
	"raw":    func() (Formatter, error) { return NewRaw() },
	"vba":    func() (Formatter, error) { return NewVBA() },
	"vbs":    func() (Formatter, error) { return NewVBS() },
}

func NewFormatter(format string) (Formatter, error) {
	factory, ok := formats[format]
	if !ok {
		return nil, fmt.Errorf("invalid format '%s' specify --formats for a list of output formats", format)
	}
	return factory()
}

func Formats() []string {
	names := make([]string, 0, len(formats))
	for name := range formats {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func formatBytes(buf []byte, perLine int, byteFormat string, seperator string, newLine string) string {
	var sb strings.Builder

	for i, b := range buf {
		if i > 0 {
			sb.WriteString(seperator)
			if i%perLine == 0 {
				sb.WriteString(newLine)
			}
		}
		fmt.Fprintf(&sb, byteFormat, b)
	}
	return sb.String()
}
