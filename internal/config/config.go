// Package config — конфигурация Auth service.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr string
	GRPCAddr string

	PostgresDSN string

	GithubClientID     string
	GithubClientSecret string
	// OAuthRedirectURL — публичный адрес нашего callback,
	// должен совпадать с настройкой GitHub OAuth App.
	OAuthRedirectURL string

	JWTPrivateKeyPath string
	TokenTTL          time.Duration

	FrontendURL   string
	SecureCookies bool

	ShutdownTimeout time.Duration
}

func Load() (Config, error) {
	var errs []error

	cfg := Config{
		HTTPAddr:           getEnv("HTTP_ADDR", ":8083"),
		GRPCAddr:           getEnv("GRPC_ADDR", ":50052"),
		PostgresDSN:        os.Getenv("POSTGRES_DSN"),
		GithubClientID:     os.Getenv("GITHUB_OAUTH_CLIENT_ID"),
		GithubClientSecret: os.Getenv("GITHUB_OAUTH_CLIENT_SECRET"),
		OAuthRedirectURL:   getEnv("OAUTH_REDIRECT_URL", "http://localhost:8083/auth/github/callback"),
		JWTPrivateKeyPath:  os.Getenv("JWT_PRIVATE_KEY_PATH"),
		TokenTTL:           time.Hour, // без refresh-токенов в MVP (спека §5)
		FrontendURL:        getEnv("FRONTEND_URL", "http://localhost:5173/"),
		SecureCookies:      strings.EqualFold(getEnv("SECURE_COOKIES", "false"), "true"),
		ShutdownTimeout:    10 * time.Second,
	}

	if cfg.PostgresDSN == "" {
		errs = append(errs, errors.New("POSTGRES_DSN обязателен"))
	}
	if cfg.JWTPrivateKeyPath == "" {
		errs = append(errs, errors.New("JWT_PRIVATE_KEY_PATH обязателен"))
	}
	if cfg.GithubClientID == "" || cfg.GithubClientSecret == "" {
		errs = append(errs, errors.New("GITHUB_OAUTH_CLIENT_ID и GITHUB_OAUTH_CLIENT_SECRET обязательны (создай GitHub OAuth App)"))
	}

	if len(errs) > 0 {
		return Config{}, fmt.Errorf("конфиг: %w", errors.Join(errs...))
	}
	return cfg, nil
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
