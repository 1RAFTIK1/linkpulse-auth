// Package token — выпуск и проверка внутренних JWT (RS256) и JWKS.
//
// RS256 (асимметричная подпись) выбран, чтобы остальные сервисы могли
// проверять токены локально по публичному ключу с JWKS-эндпоинта, без
// сетевого вызова в Auth на каждый запрос (спека §5). Централизованный
// gRPC ValidateToken остаётся для низкочастотных чувствительных операций.
package token

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const issuerName = "linkpulse-auth"

// Claims — полезная нагрузка внутреннего JWT.
type Claims struct {
	jwt.RegisteredClaims
	Username string `json:"username"` // github login
}

// Issuer выпускает подписанные токены.
type Issuer struct {
	key *rsa.PrivateKey
	kid string
	ttl time.Duration
}

// Verifier проверяет подпись и клеймы.
type Verifier struct {
	pub *rsa.PublicKey
}

// LoadPrivateKey читает RSA-ключ из PEM-файла (PKCS#1 или PKCS#8).
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- путь задаёт оператор через конфиг, не пользователь
	if err != nil {
		return nil, fmt.Errorf("чтение ключа: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("файл ключа не PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("парсинг ключа: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("ключ не RSA")
	}
	return key, nil
}

func NewIssuer(key *rsa.PrivateKey, ttl time.Duration) *Issuer {
	return &Issuer{key: key, kid: keyID(&key.PublicKey), ttl: ttl}
}

func NewVerifier(pub *rsa.PublicKey) *Verifier {
	return &Verifier{pub: pub}
}

// Issue выпускает токен для пользователя. sub = github user id.
func (i *Issuer) Issue(userID, username string, now time.Time) (string, time.Time, error) {
	expiresAt := now.Add(i.ttl)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuerName,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		Username: username,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// kid в заголовке: получатель находит нужный ключ в JWKS — задел под ротацию.
	tok.Header["kid"] = i.kid

	signed, err := tok.SignedString(i.key)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("подпись токена: %w", err)
	}
	return signed, expiresAt, nil
}

// Verify проверяет подпись, срок и издателя.
//
// jwt.WithValidMethods фиксирует РОВНО RS256: алгоритм не берётся из заголовка
// токена, что закрывает подмену RS256 → HS256 (alg confusion: публичный ключ
// стал бы HMAC-секретом и токен подделывался бы кем угодно).
func (v *Verifier) Verify(raw string) (*Claims, error) {
	var claims Claims
	_, err := jwt.ParseWithClaims(raw, &claims,
		func(*jwt.Token) (any, error) { return v.pub, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(issuerName),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("невалидный токен: %w", err)
	}
	return &claims, nil
}

// keyID — детерминированный идентификатор ключа: первые 16 байт sha256 от
// DER публичного ключа, base64url.
func keyID(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "unknown"
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// JWK — публичный ключ в формате RFC 7517 (поля RSA).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS — набор ключей для /.well-known/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// BuildJWKS собирает JWKS из публичного ключа издателя.
func (i *Issuer) BuildJWKS() JWKS {
	pub := &i.key.PublicKey
	return JWKS{Keys: []JWK{{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: i.kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
}
