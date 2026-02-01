package handlers

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"net/http"

	"local-sha256gen/crypto"
	"local-sha256gen/models"
	"local-sha256gen/storage"
)

// HandlePasswords パスワードのCRUD操作
func HandlePasswords(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		getAllPasswords(w, r)
	case http.MethodPost:
		createPassword(w, r)
	case http.MethodPut:
		updatePassword(w, r)
	case http.MethodDelete:
		deletePassword(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// getAllPasswords すべてのパスワードを取得
func getAllPasswords(w http.ResponseWriter, r *http.Request) {
	passwords := storage.GetAllPasswords()
	json.NewEncoder(w).Encode(passwords)
}

// createPassword パスワードを追加
func createPassword(w http.ResponseWriter, r *http.Request) {
	var entry models.PasswordEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// ID生成（簡易実装）
	entry.ID = generateID()

	storage.AddPassword(entry)
	if err := savePasswords(); err != nil {
		http.Error(w, "Failed to save", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(entry)
}

// updatePassword パスワードを更新
func updatePassword(w http.ResponseWriter, r *http.Request) {
	var entry models.PasswordEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if entry.ID == "" {
		http.Error(w, "ID required", http.StatusBadRequest)
		return
	}

	if !storage.UpdatePassword(entry.ID, entry) {
		http.Error(w, "Password not found", http.StatusNotFound)
		return
	}

	if err := savePasswords(); err != nil {
		http.Error(w, "Failed to save", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(entry)
}

// deletePassword パスワードを削除
func deletePassword(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID required", http.StatusBadRequest)
		return
	}

	if !storage.DeletePassword(id) {
		http.Error(w, "Password not found", http.StatusNotFound)
		return
	}

	if err := savePasswords(); err != nil {
		http.Error(w, "Failed to save", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// savePasswords パスワードを暗号化して保存
func savePasswords() error {
	masterPassword := storage.GetMasterPassword()
	salt := storage.GetMasterSalt()
	key := crypto.DeriveKey(masterPassword, salt)

	data, err := storage.GetPasswordsData()
	if err != nil {
		return err
	}

	encrypted, err := crypto.Encrypt(data, key)
	if err != nil {
		return err
	}

	return storage.SavePasswords(encrypted)
}

// generateID ID生成（簡易実装）
func generateID() string {
	// UUID風のIDを生成（簡易実装）
	return "id-" + randomString(16)
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	max := big.NewInt(int64(len(charset)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			b[i] = charset[i%len(charset)]
		} else {
			b[i] = charset[n.Int64()]
		}
	}
	return string(b)
}

// GeneratePassword パスワード生成
func GeneratePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	type GenerateRequest struct {
		Length  int  `json:"length"`
		UseUpper bool `json:"use_upper"`
		UseLower bool `json:"use_lower"`
		UseNumbers bool `json:"use_numbers"`
		UseSymbols bool `json:"use_symbols"`
	}

	type GenerateResponse struct {
		Password string `json:"password"`
	}

	var req GenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req = GenerateRequest{
			Length:     16,
			UseUpper:   true,
			UseLower:   true,
			UseNumbers: true,
			UseSymbols: false,
		}
	}

	if req.Length < 8 {
		req.Length = 8
	}
	if req.Length > 128 {
		req.Length = 128
	}

	charset := ""
	if req.UseLower {
		charset += "abcdefghijklmnopqrstuvwxyz"
	}
	if req.UseUpper {
		charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if req.UseNumbers {
		charset += "0123456789"
	}
	if req.UseSymbols {
		charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
	}

	if charset == "" {
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	}

	password := generateRandomPassword(req.Length, charset)
	json.NewEncoder(w).Encode(GenerateResponse{Password: password})
}

func generateRandomPassword(length int, charset string) string {
	b := make([]byte, length)
	max := big.NewInt(int64(len(charset)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			// フォールバック（簡易実装）
			b[i] = charset[i%len(charset)]
		} else {
			b[i] = charset[n.Int64()]
		}
	}
	return string(b)
}
