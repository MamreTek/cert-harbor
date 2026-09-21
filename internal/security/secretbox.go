package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

type SecretBox struct {
	key [32]byte
}

func NewSecretBox(keyMaterial string) (*SecretBox, error) {
	if keyMaterial == "" {
		return nil, errors.New("encryption key material is required")
	}
	return &SecretBox{key: sha256.Sum256([]byte(keyMaterial))}, nil
}

func (s *SecretBox) Encrypt(value []byte) (string, error) {
	block, err := aes.NewCipher(s.key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, value, nil)
	return "v1:" + base64.RawStdEncoding.EncodeToString(append(nonce, ciphertext...)), nil
}

func (s *SecretBox) Decrypt(value string) ([]byte, error) {
	const prefix = "v1:"
	if len(value) <= len(prefix) || value[:len(prefix)] != prefix {
		return nil, errors.New("unsupported encrypted secret format")
	}
	data, err := base64.RawStdEncoding.DecodeString(value[len(prefix):])
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(s.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("encrypted secret is truncated")
	}
	return gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
}

func (s *SecretBox) EncryptMap(values map[string]string) (string, error) {
	data, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return s.Encrypt(data)
}

func (s *SecretBox) DecryptMap(value string) (map[string]string, error) {
	data, err := s.Decrypt(value)
	if err != nil {
		return nil, err
	}
	var values map[string]string
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, err
	}
	return values, nil
}
