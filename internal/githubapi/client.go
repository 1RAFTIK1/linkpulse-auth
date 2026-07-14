// Package githubapi — OAuth-обмен и получение профиля пользователя GitHub.
package githubapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const userAPI = "https://api.github.com/user"

// Profile — минимум полей профиля, которые нам нужны.
type Profile struct {
	ID        string // числовой id GitHub, приводим к строке — это users.id
	Login     string
	AvatarURL string
}

type Client struct {
	oauth *oauth2.Config
	http  *http.Client
}

// New: redirectURL — наш /auth/github/callback; скоупы не запрашиваем,
// публичного профиля достаточно.
func New(clientID, clientSecret, redirectURL string) *Client {
	return &Client{
		oauth: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     github.Endpoint,
		},
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

// AuthURL — куда редиректить браузер; state защищает от CSRF.
func (c *Client) AuthURL(state string) string {
	return c.oauth.AuthCodeURL(state)
}

// Exchange меняет одноразовый code на access token GitHub.
// Обмен НЕ ретраим: code одноразовый, повтор после частичного успеха
// гарантированно вернёт ошибку и замаскирует настоящую причину.
func (c *Client) Exchange(ctx context.Context, code string) (string, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.http)
	tok, err := c.oauth.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("обмен кода: %w", err)
	}
	return tok.AccessToken, nil
}

// FetchProfile запрашивает профиль. Читающий GET безопасно ретраить —
// до 3 попыток с экспоненциальным backoff (спека §11: свой минимальный
// retry вместо библиотеки — меньше магии).
func (c *Client) FetchProfile(ctx context.Context, accessToken string) (Profile, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<attempt) * 250 * time.Millisecond // 500ms, 1s
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return Profile{}, ctx.Err()
			}
		}
		p, retriable, err := c.fetchOnce(ctx, accessToken)
		if err == nil {
			return p, nil
		}
		lastErr = err
		if !retriable {
			return Profile{}, err
		}
	}
	return Profile{}, fmt.Errorf("профиль github после ретраев: %w", lastErr)
}

func (c *Client) fetchOnce(ctx context.Context, accessToken string) (Profile, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userAPI, nil)
	if err != nil {
		return Profile{}, false, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.http.Do(req)
	if err != nil {
		return Profile{}, true, err // сетевые ошибки ретраим
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		// 5xx — ретраим, 4xx (протухший токен и т.п.) — нет.
		return Profile{}, resp.StatusCode >= 500,
			fmt.Errorf("github api: статус %d", resp.StatusCode)
	}

	var raw struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return Profile{}, false, fmt.Errorf("декодирование профиля: %w", err)
	}
	return Profile{
		ID:        strconv.FormatInt(raw.ID, 10),
		Login:     raw.Login,
		AvatarURL: raw.AvatarURL,
	}, false, nil
}
