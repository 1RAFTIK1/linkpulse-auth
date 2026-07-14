# linkpulse-auth

Auth service проекта **LinkPulse**: вход через GitHub OAuth, выпуск внутренних
JWT (RS256), JWKS для локальной проверки подписи другими сервисами и gRPC
`ValidateToken` для централизованной проверки.

## Потоки

**Логин (браузер):**
```
GET /auth/github/login  → state-cookie + redirect на GitHub
GET /auth/github/callback?code&state
    → проверка state (анти-CSRF)
    → code → access token → профиль GitHub (retry с backoff)
    → upsert в users
    → выпуск JWT (RS256, kid, TTL 1 час, без refresh в MVP)
    → redirect FRONTEND_URL#token=<jwt>   (fragment: не попадает в логи)
```

**Проверка токена другими сервисами (спека §5):**
- Горячие пути — локально по публичному ключу из `GET /.well-known/jwks.json`.
- Чувствительные операции (создание ссылок, WS-авторизация) — gRPC
  `ValidateToken` → `{valid, user_id, github_username, expires_at}`.

## Безопасность — ключевые решения

- **RS256 строго по allow-list** при верификации: закрыта подмена алгоритма
  RS256 → HS256 (есть регресс-тест).
- **`state` в OAuth** — HttpOnly cookie, SameSite=Lax, TTL 10 минут,
  одноразовый; без него возможен login CSRF.
- Токен возвращается во **fragment** URL, не в query.
- Невалидный токен в `ValidateToken` — это `{valid:false}`, а не ошибка RPC:
  сбой транспорта и «плохой токен» различимы для вызывающего.

## Конфигурация (env)

| Переменная | Дефолт | Описание |
|---|---|---|
| `POSTGRES_DSN` | — (обязательна) | БД linkpulse_auth |
| `JWT_PRIVATE_KEY_PATH` | — (обязательна) | RSA-ключ PEM (`make keys` для dev) |
| `GITHUB_OAUTH_CLIENT_ID` | — (обязательна) | из GitHub OAuth App |
| `GITHUB_OAUTH_CLIENT_SECRET` | — (обязательна) | из GitHub OAuth App |
| `OAUTH_REDIRECT_URL` | `http://localhost:8083/auth/github/callback` | callback (совпадает с OAuth App) |
| `FRONTEND_URL` | `http://localhost:5173/` | куда вернуть браузер с токеном |
| `HTTP_ADDR` / `GRPC_ADDR` | `:8083` / `:50052` | адреса серверов |
| `SECURE_COOKIES` | `false` | true в проде (https) |

GitHub OAuth App создаётся в Settings → Developer settings → OAuth Apps;
callback URL = `OAUTH_REDIRECT_URL`.

## Запуск локально

```bash
make keys                      # dev-ключ RSA (не коммитится)
make tools && make migrate-up  # миграции
GITHUB_OAUTH_CLIENT_ID=... GITHUB_OAUTH_CLIENT_SECRET=... make run
```

Для отладки без OAuth есть dev-утилита:

```bash
go run ./cmd/devtoken -key keys/jwt-private.pem -user 999 -username tester
# печатает JWT, подписанный тем же ключом — годится для curl и wscat
```

## Данные (Postgres, БД linkpulse_auth)

```sql
users(id TEXT PK,          -- числовой GitHub user id (стабилен, в отличие от login)
      github_username TEXT, avatar_url TEXT,
      created_at, updated_at TIMESTAMPTZ)
```

## Зависимости и версии

| Библиотека | Версия | Роль |
|---|---|---|
| golang-jwt/jwt/v5 | 5.3.1 | выпуск/проверка JWT |
| golang.org/x/oauth2 | 0.36.0 | OAuth-обмен с GitHub |
| jackc/pgx/v5 | 5.10.0 | Postgres |

Go 1.26.
