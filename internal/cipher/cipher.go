package cipher

import (
	"fmt"
	"sort"
)

type KeySpec struct {
	KeySize   int
	NonceSize int // 0 = no nonce required
}

var specs = map[string]KeySpec{
	"aes":      {KeySize: 16, NonceSize: 16},
	"chacha20": {KeySize: 32, NonceSize: 12},
	"rc4":      {KeySize: 16, NonceSize: 0},
	"salsa20":  {KeySize: 32, NonceSize: 8},
	"xor":      {KeySize: 16, NonceSize: 0},
}

func Spec(method string) (KeySpec, error) {
	spec, ok := specs[method]
	if !ok {
		// given argument filtering this shouldn't occur
		return KeySpec{}, fmt.Errorf("unknown cipher: %s", method)
	}
	return spec, nil
}

type Cipher interface {
	Encrypt(plaintext []byte) ([]byte, error)
}

type factory func(key, nonce []byte) (Cipher, error)

var ciphers = map[string]factory{
	"aes":      func(key []byte, nonce []byte) (Cipher, error) { return NewAES(key, nonce) },
	"chacha20": func(key []byte, nonce []byte) (Cipher, error) { return NewChaCha20(key, nonce) },
	"rc4":      func(key []byte, nonce []byte) (Cipher, error) { return NewRC4(key) },
	"salsa20":  func(key []byte, nonce []byte) (Cipher, error) { return NewSalsa20(key, nonce) },
	"xor":      func(key []byte, nonce []byte) (Cipher, error) { return NewXOR(key) },
}

func NewCipher(method string, key []byte, nonce []byte) (Cipher, error) {
	factory, ok := ciphers[method]
	if !ok {
		return nil, fmt.Errorf("unknown cipher: '%s' specify --ciphers for a list of ciphers", method)
	}
	return factory(key, nonce)
}

func Ciphers() []string {
	names := make([]string, 0, len(ciphers))
	for name := range ciphers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
