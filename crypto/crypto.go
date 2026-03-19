package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// GenerateKey generates a random 32-byte AES-256 key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateNonce generates a random 12-byte nonce for AES-GCM.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// Encrypt encrypts plaintext using AES-256-GCM. Returns ciphertext and nonce.
func Encrypt(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = GenerateNonce()
	if err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM.
func Decrypt(key, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// EncryptDEK encrypts a DEK with a KEK (envelope encryption).
func EncryptDEK(kek, dek []byte) (ciphertext, nonce []byte, err error) {
	return Encrypt(kek, dek)
}

// DecryptDEK decrypts a DEK that was encrypted with a KEK.
func DecryptDEK(kek, encryptedDEK, nonce []byte) ([]byte, error) {
	return Decrypt(kek, encryptedDEK, nonce)
}

// EncodeCiphertext encodes ciphertext and nonce as "base64(cipher):base64(nonce)".
func EncodeCiphertext(ciphertext, nonce []byte) string {
	return base64.StdEncoding.EncodeToString(ciphertext) + ":" + base64.StdEncoding.EncodeToString(nonce)
}

// DecodeCiphertext decodes a "base64(cipher):base64(nonce)" string.
func DecodeCiphertext(encoded string) (ciphertext, nonce []byte, err error) {
	parts := strings.SplitN(encoded, ":", 2)
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("invalid ciphertext format: expected cipher:nonce")
	}
	ciphertext, err = base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	nonce, err = base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("decode nonce: %w", err)
	}
	return ciphertext, nonce, nil
}

// GenerateUUID generates a random UUID v4.
func GenerateUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// GenerateHexRef generates a random lowercase hex string of the given length.
// Used for generating secret ref IDs.
func GenerateHexRef(length int) (string, error) {
	b := make([]byte, (length+1)/2)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b)[:length], nil
}

// GenerateShortHash generates a short CK:xxxxxxxx hash from an encrypted value.
func GenerateShortHash(encryptedValue []byte) string {
	hash := sha256.Sum256(encryptedValue)
	return fmt.Sprintf("CK:%s", hex.EncodeToString(hash[:])[:8])
}
