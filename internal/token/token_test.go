package token

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestIssueVerify_RoundTrip(t *testing.T) {
	key := testKey(t)
	iss := NewIssuer(key, time.Hour)
	ver := NewVerifier(&key.PublicKey)
	now := time.Now()

	raw, expiresAt, err := iss.Issue("12345", "octocat", now)
	if err != nil {
		t.Fatal(err)
	}
	if got := expiresAt.Sub(now); got != time.Hour {
		t.Errorf("ttl=%v", got)
	}

	claims, err := ver.Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "12345" || claims.Username != "octocat" {
		t.Errorf("claims: %+v", claims)
	}
}

func TestVerify_Expired(t *testing.T) {
	key := testKey(t)
	iss := NewIssuer(key, time.Minute)
	ver := NewVerifier(&key.PublicKey)

	raw, _, err := iss.Issue("1", "u", time.Now().Add(-2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ver.Verify(raw); err == nil {
		t.Fatal("просроченный токен должен отклоняться")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	iss := NewIssuer(testKey(t), time.Hour)
	ver := NewVerifier(&testKey(t).PublicKey) // другой ключ

	raw, _, _ := iss.Issue("1", "u", time.Now())
	if _, err := ver.Verify(raw); err == nil {
		t.Fatal("токен с чужой подписью должен отклоняться")
	}
}

func TestVerify_RejectsAlgConfusion(t *testing.T) {
	key := testKey(t)
	ver := NewVerifier(&key.PublicKey)

	// Токен HS256, «подписанный» публичным ключом как HMAC-секретом, —
	// классическая подмена алгоритма. Verify обязан отклонить по allow-list.
	claims := jwt.RegisteredClaims{
		Issuer:    "linkpulse-auth",
		Subject:   "attacker",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	raw, err := forged.SignedString([]byte("whatever"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ver.Verify(raw); err == nil {
		t.Fatal("HS256-токен должен отклоняться (alg confusion)")
	}
}

func TestVerify_WrongIssuer(t *testing.T) {
	key := testKey(t)
	ver := NewVerifier(&key.PublicKey)

	claims := jwt.RegisteredClaims{
		Issuer:    "evil-issuer",
		Subject:   "1",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ver.Verify(raw); err == nil {
		t.Fatal("чужой issuer должен отклоняться")
	}
}

func TestBuildJWKS(t *testing.T) {
	iss := NewIssuer(testKey(t), time.Hour)
	jwks := iss.BuildJWKS()

	if len(jwks.Keys) != 1 {
		t.Fatalf("ключей %d", len(jwks.Keys))
	}
	k := jwks.Keys[0]
	if k.Kty != "RSA" || k.Alg != "RS256" || k.Use != "sig" {
		t.Errorf("метаданные: %+v", k)
	}
	if k.N == "" || k.E == "" || k.Kid == "" {
		t.Error("пустые поля JWK")
	}
	if strings.ContainsAny(k.N, "+/=") {
		t.Error("N должен быть base64url без паддинга")
	}
}
