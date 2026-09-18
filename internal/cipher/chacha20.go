package cipher

import "fmt"
import "golang.org/x/crypto/chacha20"

var _ Cipher = (*ChaCha20)(nil)

type ChaCha20 struct {
	key   []byte
	nonce []byte
}

func NewChaCha20(key []byte, nonce []byte) (*ChaCha20, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("chacha20 requires 32-byte key, got %d", len(key))
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("chacha20 requires a 12-byte nonce, got %d", len(nonce))
	}
	return &ChaCha20{key: key, nonce: nonce}, nil
}

func (c *ChaCha20) Encrypt(plaintext []byte) ([]byte, error) {
	out := make([]byte, len(plaintext))
	cipher, err := chacha20.NewUnauthenticatedCipher(c.key, c.nonce)
	if err != nil {
		return nil, err
	}
	cipher.XORKeyStream(out, plaintext)
	return out, nil
}
