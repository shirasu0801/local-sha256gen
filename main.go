package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"local-sha256gen/handlers"
	"local-sha256gen/storage"
)

func main() {
	// データディレクトリの作成
	dataDir := filepath.Join(os.Getenv("APPDATA"), "local-sha256gen")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		log.Fatalf("データディレクトリの作成に失敗しました: %v", err)
	}

	// ストレージの初期化
	storage.Init(dataDir)

	// ルーティング設定
	mux := http.NewServeMux()

	// 静的ファイル
	mux.Handle("/", http.FileServer(http.Dir("./static")))

	// APIエンドポイント
	mux.HandleFunc("/api/auth/login", handlers.Login)
	mux.HandleFunc("/api/auth/verify", handlers.VerifyAuth)
	mux.HandleFunc("/api/passwords", handlers.HandlePasswords)
	mux.HandleFunc("/api/passwords/generate", handlers.GeneratePassword)

	port := ":8080"
	log.Printf("サーバーを起動しました: http://localhost%s", port)
	if err := http.ListenAndServe(port, mux); err != nil {
		log.Fatalf("サーバーの起動に失敗しました: %v", err)
	}
}
