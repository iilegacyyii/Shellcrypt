package cipher

import "fmt"
import "golang.org/x/crypto/salsa20"

var _ Cipher = (*Salsa20)(nil)

type Salsa20 struct {
	key   []byte
	nonce []byte
}

func NewSalsa20(key []byte, nonce []byte) (*Salsa20, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("salsa20 requires 32-byte key, got %d", len(key))
	}
	if len(nonce) != 8 {
		return nil, fmt.Errorf("salsa20 requires an 8-byte nonce, got %d", len(nonce))
	}
	return &Salsa20{key: key, nonce: nonce}, nil
}

func (s *Salsa20) Encrypt(plaintext []byte) ([]byte, error) {
	var k [32]byte
	copy(k[:], s.key)
	out := make([]byte, len(plaintext))
	salsa20.XORKeyStream(out, plaintext, s.nonce, &k)
	return out, nil
}
