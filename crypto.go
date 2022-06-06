package mfast

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
)

func h(msg []byte) []byte {
	hash := sha256.New()
	hash.Write(msg)
	return hash.Sum(nil)
}

func h1(msg []byte) []byte {
	mac := hmac.New(sha256.New, []byte{1})
	mac.Write(msg)
	return mac.Sum(nil)
}

func h2(msg []byte) []byte {
	mac := hmac.New(sha256.New, []byte{2})
	mac.Write(msg)
	return mac.Sum(nil)
}

func p(key, raw []byte) []byte {
	if len(raw) != 32 {
		panic("mfast: Input length of prfP must be 32")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, 32)
	block.Encrypt(ciphertext, raw)

	return ciphertext
}

func invP(key, ciphertext []byte) []byte {
	if len(ciphertext) != 32 {
		panic("input length of prfP must be 32")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	raw := make([]byte, 32)
	block.Decrypt(raw, ciphertext)

	return raw
}
