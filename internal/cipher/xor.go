package cipher

import "fmt"

var _ Cipher = (*XOR)(nil)

type XOR struct {
	key []byte
}

func NewXOR(key []byte) (*XOR, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key must not be empty")
	}
	return &XOR{key: key}, nil
}

func (x *XOR) Encrypt(plaintext []byte) ([]byte, error) {
	out := make([]byte, len(plaintext))
	for i, b := range plaintext {
		out[i] = b ^ x.key[i%len(x.key)]
	}
	return out, nil
}
