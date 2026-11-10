package crypto

import (
	"bytes"
	"fmt"
	"testing"
)

func TestEncryptDecryptValidAESKeys(t *testing.T) {
	for _, keySize := range []int{16, 24, 32} {
		for _, plaintext := range [][]byte{nil, []byte("round trip")} {
			t.Run(fmt.Sprintf("key_%d/plaintext_%d", keySize, len(plaintext)), func(t *testing.T) {
				key := make([]byte, keySize)
				ciphertext, nonce, err := Encrypt(key, plaintext)
				if err != nil {
					t.Fatal(err)
				}
				if len(nonce) != 12 || len(ciphertext) != len(plaintext)+16 {
					t.Fatalf("unexpected GCM lengths: nonce=%d ciphertext=%d", len(nonce), len(ciphertext))
				}
				got, err := Decrypt(key, ciphertext, nonce)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatal("plaintext did not round trip")
				}
			})
		}
	}
}

func TestEncryptDecryptRejectInvalidAESKeys(t *testing.T) {
	for _, keySize := range []int{0, 1, 15, 17, 23, 25, 31, 33} {
		t.Run(fmt.Sprintf("key_%d", keySize), func(t *testing.T) {
			key := make([]byte, keySize)
			ciphertext, nonce, err := Encrypt(key, nil)
			if err == nil || ciphertext != nil || nonce != nil {
				t.Fatal("Encrypt must return an error and no output for an invalid key")
			}
			plaintext, err := Decrypt(key, make([]byte, 16), make([]byte, 12))
			if err == nil || plaintext != nil {
				t.Fatal("Decrypt must return an error and no output for an invalid key")
			}
		})
	}
}

func TestDecryptRejectsInvalidNonceLength(t *testing.T) {
	key := make([]byte, 32)
	ciphertext, _, err := Encrypt(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, nonceSize := range []int{0, 1, 11, 13, 24} {
		t.Run(fmt.Sprintf("nonce_%d", nonceSize), func(t *testing.T) {
			plaintext, err := Decrypt(key, ciphertext, make([]byte, nonceSize))
			if err == nil || plaintext != nil {
				t.Fatal("Decrypt must return an error and no output for an invalid nonce")
			}
		})
	}
}

func TestDecryptRejectsShortCiphertext(t *testing.T) {
	for _, size := range []int{0, 1, 15} {
		t.Run(fmt.Sprintf("ciphertext_%d", size), func(t *testing.T) {
			plaintext, err := Decrypt(make([]byte, 32), make([]byte, size), make([]byte, 12))
			if err == nil || plaintext != nil {
				t.Fatal("Decrypt must return an error and no output for a truncated authentication tag")
			}
		})
	}
}

func TestDecryptRejectsModifiedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	ciphertext, nonce, err := Encrypt(key, []byte("round trip"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 1
	if plaintext, err := Decrypt(key, ciphertext, nonce); err == nil || plaintext != nil {
		t.Fatal("Decrypt must reject modified ciphertext")
	}
}

func TestDecryptDEKRejectsInvalidNonceLength(t *testing.T) {
	if plaintext, err := DecryptDEK(make([]byte, 32), make([]byte, 16), []byte{0}); err == nil || plaintext != nil {
		t.Fatal("DecryptDEK must return an error and no output for an invalid nonce")
	}
}
