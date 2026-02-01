package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	SaltSize   = 32
	nonceSize  = 12 // GCM用
	keySize    = 32 // AES-256
	iterations = 100000
)

// DeriveKey マスターパスワードからAES-256キーを生成
func DeriveKey(masterPassword string, salt []byte) []byte {
	return pbkdf2.Key([]byte(masterPassword), salt, iterations, keySize, sha256.New)
}

// Encrypt データをAES-256-GCMで暗号化
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt データをAES-256-GCMで復号化
func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// HashPassword パスワードのハッシュ化（マスターパスワード検証用）
func HashPassword(password string, salt []byte) string {
	hash := pbkdf2.Key([]byte(password), salt, iterations, keySize, sha256.New)
	return base64.StdEncoding.EncodeToString(hash)
}

// VerifyPassword パスワードの検証
func VerifyPassword(password string, salt []byte, hashedPassword string) bool {
	hash := HashPassword(password, salt)
	return hash == hashedPassword
}
