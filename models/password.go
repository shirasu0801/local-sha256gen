package models

// PasswordEntry パスワードエントリの構造体
type PasswordEntry struct {
	ID       string `json:"id"`
	Service  string `json:"service"`
	URL      string `json:"url"`
	UserID   string `json:"user_id"`
	Password string `json:"password"`
}
