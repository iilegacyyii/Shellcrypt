package cipher

import "fmt"
import "crypto/rc4"

var _ Cipher = (*RC4)(nil)

type RC4 struct {
	key []byte
}

func NewRC4(key []byte) (*RC4, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key must not be empty")
	}
	return &RC4{key: key}, nil
}

func (r *RC4) Encrypt(plaintext []byte) ([]byte, error) {
	out := make([]byte, len(plaintext))
	c, err := rc4.NewCipher(r.key)
	if err != nil {
		return nil, err
	}
	c.XORKeyStream(out, plaintext)
	return out, nil
}
