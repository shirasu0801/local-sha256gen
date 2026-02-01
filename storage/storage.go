package storage

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"local-sha256gen/crypto"
	"local-sha256gen/models"
)

var (
	dataFile       string
	masterFile     string
	masterPassword string
	masterHash     string
	masterSalt     []byte
	passwords      []models.PasswordEntry
	mu             sync.RWMutex
)

// Init ストレージの初期化
func Init(dataDir string) {
	dataFile = filepath.Join(dataDir, "passwords.dat")
	masterFile = filepath.Join(dataDir, "master.dat")
	passwords = make([]models.PasswordEntry, 0)
	loadMasterPassword()
}

// loadMasterPassword マスターパスワード情報を読み込む
func loadMasterPassword() {
	data, err := os.ReadFile(masterFile)
	if err != nil {
		return
	}

	var masterData struct {
		Hash string `json:"hash"`
		Salt string `json:"salt"`
	}

	if err := json.Unmarshal(data, &masterData); err != nil {
		return
	}

	masterHash = masterData.Hash
	saltBytes, err := base64.StdEncoding.DecodeString(masterData.Salt)
	if err != nil {
		return
	}
	masterSalt = saltBytes
}

// saveMasterPassword マスターパスワード情報を保存
func saveMasterPassword() error {
	masterData := struct {
		Hash string `json:"hash"`
		Salt string `json:"salt"`
	}{
		Hash: masterHash,
		Salt: base64.StdEncoding.EncodeToString(masterSalt),
	}

	data, err := json.Marshal(masterData)
	if err != nil {
		return err
	}

	return os.WriteFile(masterFile, data, 0600)
}

// SetMasterPassword マスターパスワードを設定
func SetMasterPassword(password string, salt []byte, hash string) error {
	mu.Lock()
	defer mu.Unlock()
	masterPassword = password
	masterSalt = salt
	masterHash = hash
	return saveMasterPassword()
}

// GetMasterPassword マスターパスワードを取得（暗号化キー生成用）
func GetMasterPassword() string {
	mu.RLock()
	defer mu.RUnlock()
	return masterPassword
}

// GetMasterSalt マスターパスワードのソルトを取得
func GetMasterSalt() []byte {
	mu.RLock()
	defer mu.RUnlock()
	return masterSalt
}

// HasMasterPassword マスターパスワードが設定されているか確認
func HasMasterPassword() bool {
	mu.RLock()
	defer mu.RUnlock()
	return masterHash != ""
}

// VerifyMasterPassword マスターパスワードの検証
func VerifyMasterPassword(password string) bool {
	mu.RLock()
	defer mu.RUnlock()
	if masterHash == "" {
		return false
	}
	return crypto.VerifyPassword(password, masterSalt, masterHash)
}

// LoadPasswords パスワードデータを読み込む
func LoadPasswords(decryptedData []byte) error {
	mu.Lock()
	defer mu.Unlock()

	if len(decryptedData) == 0 {
		passwords = make([]models.PasswordEntry, 0)
		return nil
	}

	return json.Unmarshal(decryptedData, &passwords)
}

// SavePasswords パスワードデータを保存
func SavePasswords(encryptedData []byte) error {
	mu.Lock()
	defer mu.Unlock()

	return os.WriteFile(dataFile, encryptedData, 0600)
}

// GetAllPasswords すべてのパスワードを取得
func GetAllPasswords() []models.PasswordEntry {
	mu.RLock()
	defer mu.RUnlock()

	result := make([]models.PasswordEntry, len(passwords))
	copy(result, passwords)
	return result
}

// AddPassword パスワードを追加
func AddPassword(entry models.PasswordEntry) {
	mu.Lock()
	defer mu.Unlock()
	passwords = append(passwords, entry)
}

// UpdatePassword パスワードを更新
func UpdatePassword(id string, entry models.PasswordEntry) bool {
	mu.Lock()
	defer mu.Unlock()

	for i, p := range passwords {
		if p.ID == id {
			entry.ID = id
			passwords[i] = entry
			return true
		}
	}
	return false
}

// DeletePassword パスワードを削除
func DeletePassword(id string) bool {
	mu.Lock()
	defer mu.Unlock()

	for i, p := range passwords {
		if p.ID == id {
			passwords = append(passwords[:i], passwords[i+1:]...)
			return true
		}
	}
	return false
}

// GetPasswordsData パスワードデータをJSON形式で取得（暗号化前）
func GetPasswordsData() ([]byte, error) {
	mu.RLock()
	defer mu.RUnlock()
	return json.Marshal(passwords)
}
