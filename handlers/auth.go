package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"

	"local-sha256gen/crypto"
	"local-sha256gen/storage"
)

type LoginRequest struct {
	Password string `json:"password"`
}

type LoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
}

type VerifyRequest struct {
	Token string `json:"token"`
}

type VerifyResponse struct {
	Valid bool `json:"valid"`
}

// セッション管理用（簡易実装）
var sessionToken string

// Login マスターパスワードでログイン
func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Password == "" {
		http.Error(w, "Password required", http.StatusBadRequest)
		return
	}

	// マスターパスワードが設定されていない場合、新規作成
	if !storage.HasMasterPassword() {
		// ソルト生成
		salt := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			http.Error(w, "Failed to generate salt", http.StatusInternalServerError)
			return
		}

		// ハッシュ生成
		hash := crypto.HashPassword(req.Password, salt)

		// マスターパスワード設定
		if err := storage.SetMasterPassword(req.Password, salt, hash); err != nil {
			http.Error(w, "Failed to save master password", http.StatusInternalServerError)
			return
		}

		// 既存データがあれば読み込む
		dataFile := os.Getenv("APPDATA") + "\\local-sha256gen\\passwords.dat"
		if data, err := os.ReadFile(dataFile); err == nil && len(data) > 0 {
			key := crypto.DeriveKey(req.Password, salt)
			if decrypted, err := crypto.Decrypt(data, key); err == nil {
				storage.LoadPasswords(decrypted)
			}
		}

		// セッショントークン生成
		tokenBytes := make([]byte, 32)
		rand.Read(tokenBytes)
		sessionToken = base64.StdEncoding.EncodeToString(tokenBytes)

		json.NewEncoder(w).Encode(LoginResponse{
			Success: true,
			Message: "マスターパスワードを設定しました",
			Token:   sessionToken,
		})
		return
	}

	// 既存のマスターパスワードでログイン
	if !storage.VerifyMasterPassword(req.Password) {
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "パスワードが正しくありません",
		})
		return
	}

	// データを読み込む
	dataFile := os.Getenv("APPDATA") + "\\local-sha256gen\\passwords.dat"
	if data, err := os.ReadFile(dataFile); err == nil && len(data) > 0 {
		salt := storage.GetMasterSalt()
		key := crypto.DeriveKey(req.Password, salt)
		if decrypted, err := crypto.Decrypt(data, key); err == nil {
			storage.LoadPasswords(decrypted)
		}
	}

	// セッショントークン生成
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	sessionToken = base64.StdEncoding.EncodeToString(tokenBytes)

	json.NewEncoder(w).Encode(LoginResponse{
		Success: true,
		Message: "ログイン成功",
		Token:   sessionToken,
	})
}

// VerifyAuth 認証トークンの検証
func VerifyAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	valid := req.Token != "" && req.Token == sessionToken
	json.NewEncoder(w).Encode(VerifyResponse{Valid: valid})
}

// checkAuth 認証チェック（内部関数）
func checkAuth(r *http.Request) bool {
	token := r.Header.Get("Authorization")
	if token == "" {
		return false
	}
	return token == sessionToken
}
