package formatter

var _ Formatter = (*Raw)(nil)

type Raw struct{}

func NewRaw() (*Raw, error) {
	return &Raw{}, nil
}

func (c *Raw) Generate(ciphertext []byte, key []byte, nonce []byte) string {
	return string(ciphertext)
}
