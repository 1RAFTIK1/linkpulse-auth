// Package httpapi — HTTP-слой Auth service: OAuth-флоу GitHub, JWKS, healthz.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/1RAFTIK1/linkpulse-auth/internal/githubapi"
	"github.com/1RAFTIK1/linkpulse-auth/internal/storage"
	"github.com/1RAFTIK1/linkpulse-auth/internal/token"
)

const (
	// stateCookie хранит анти-CSRF state между login и callback.
	// Без него злоумышленник может скормить жертве свой code и привязать
	// её сессию к своему аккаунту (login CSRF).
	stateCookie = "oauth_state"
	stateTTL    = 10 * time.Minute
)

type Users interface {
	UpsertUser(ctx context.Context, u storage.User) error
	Ping(ctx context.Context) error
}

type Handlers struct {
	gh     *githubapi.Client
	users  Users
	issuer *token.Issuer
	// frontendURL — куда возвращаем браузер с токеном (адрес SPA).
	frontendURL string
	// secureCookies=false только для локального http; в проде всегда true.
	secureCookies bool
	log           *slog.Logger
}

func NewHandlers(gh *githubapi.Client, users Users, issuer *token.Issuer, frontendURL string, secureCookies bool, log *slog.Logger) *Handlers {
	return &Handlers{gh: gh, users: users, issuer: issuer, frontendURL: frontendURL, secureCookies: secureCookies, log: log}
}

// Login — GET /auth/github/login: ставим state-cookie и уводим на GitHub.
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	state := randomHex(16)
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookie,
		Value:    state,
		Path:     "/auth/github",
		MaxAge:   int(stateTTL.Seconds()),
		HttpOnly: true, // JS не читает — только браузерный редирект-флоу
		Secure:   h.secureCookies,
		SameSite: http.SameSiteLaxMode, // Lax: cookie едет на top-level redirect с GitHub
	})
	http.Redirect(w, r, h.gh.AuthURL(state), http.StatusFound)
}

// Callback — GET /auth/github/callback?code=...&state=...
func (h *Handlers) Callback(w http.ResponseWriter, r *http.Request) {
	// 1. Анти-CSRF: state из query обязан совпасть со state из нашей cookie.
	cookie, err := r.Cookie(stateCookie)
	if err != nil || cookie.Value == "" || r.URL.Query().Get("state") != cookie.Value {
		h.log.Warn("callback: несовпадение state", "remote", r.RemoteAddr)
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	// Одноразовость: сразу гасим cookie.
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Path: "/auth/github", MaxAge: -1})

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// 2. code → access token GitHub.
	accessToken, err := h.gh.Exchange(ctx, code)
	if err != nil {
		h.log.Error("oauth exchange", "error", err)
		http.Error(w, "oauth exchange failed", http.StatusBadGateway)
		return
	}

	// 3. Профиль → upsert пользователя.
	profile, err := h.gh.FetchProfile(ctx, accessToken)
	if err != nil {
		h.log.Error("получение профиля", "error", err)
		http.Error(w, "github profile failed", http.StatusBadGateway)
		return
	}
	if err := h.users.UpsertUser(ctx, storage.User{
		ID:             profile.ID,
		GithubUsername: profile.Login,
		AvatarURL:      profile.AvatarURL,
	}); err != nil {
		h.log.Error("upsert user", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 4. Внутренний JWT → редирект на фронтенд.
	jwt, _, err := h.issuer.Issue(profile.ID, profile.Login, time.Now())
	if err != nil {
		h.log.Error("выпуск токена", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.log.Info("пользователь вошёл", "user_id", profile.ID, "username", profile.Login)
	// Токен во fragment (#), не в query: фрагмент не уходит на сервер,
	// не оседает в access-логах и не утекает через Referer.
	http.Redirect(w, r, h.frontendURL+"#token="+jwt, http.StatusFound)
}

// JWKS — GET /.well-known/jwks.json: публичный ключ для локальной проверки
// подписи другими сервисами.
func (h *Handlers) JWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Ключ меняется только с рестартом сервиса — смело кэшируем.
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(h.issuer.BuildJWKS())
}

// Healthz — GET /healthz.
func (h *Handlers) Healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := h.users.Ping(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("postgres: " + err.Error()))
		return
	}
	_, _ = w.Write([]byte("ok"))
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
