// devtoken — dev-утилита: выпускает JWT тем же ключом, что и сервис,
// минуя GitHub OAuth. Для локальной отладки и нагрузочных тестов,
// где браузерный OAuth-флоу невозможен. В прод-образ не попадает.
//
// Использование: devtoken -key keys/jwt-private.pem -user 999 -username tester
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/1RAFTIK1/linkpulse-auth/internal/token"
)

func main() {
	keyPath := flag.String("key", "keys/jwt-private.pem", "путь к приватному ключу PEM")
	userID := flag.String("user", "999", "user id (sub)")
	username := flag.String("username", "dev-user", "github username claim")
	ttl := flag.Duration("ttl", time.Hour, "срок жизни токена")
	flag.Parse()

	key, err := token.LoadPrivateKey(*keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}

	jwt, expiresAt, err := token.NewIssuer(key, *ttl).Issue(*userID, *username, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "expires:", expiresAt.Format(time.RFC3339))
	fmt.Println(jwt)
}
