package cipher

import (
	"crypto/aes"
	stdcipher "crypto/cipher"
	"fmt"
)

var _ Cipher = (*AES)(nil)

type AES struct {
	key   []byte
	nonce []byte
}

func NewAES(key []byte, nonce []byte) (*AES, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("aes128-cbc  requires 16-byte key, got %d", len(key))
	}
	if len(nonce) != 16 {
		return nil, fmt.Errorf("aes128-cbc requires a 16-byte nonce, got %d", len(nonce))
	}
	return &AES{key: key, nonce: nonce}, nil
}

func (a *AES) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	padded := pkcs7pad(plaintext, aes.BlockSize)
	out := make([]byte, len(padded))
	mode := stdcipher.NewCBCEncrypter(block, a.nonce)
	mode.CryptBlocks(out, padded)
	return out, nil
}

func pkcs7pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}
