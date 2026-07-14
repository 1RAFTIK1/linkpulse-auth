// Package storage — таблица users в Postgres.
package storage

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type User struct {
	ID             string
	GithubUsername string
	AvatarURL      string
}

type Postgres struct {
	pool *pgxpool.Pool
}

func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("создание пула: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Close() { p.pool.Close() }

func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

// UpsertUser создаёт пользователя при первом логине и обновляет профиль
// при повторных (логин/аватар на GitHub могли смениться).
func (p *Postgres) UpsertUser(ctx context.Context, u User) error {
	const q = `
		INSERT INTO users (id, github_username, avatar_url)
		VALUES ($1, $2, $3)
		ON CONFLICT (id) DO UPDATE
		SET github_username = EXCLUDED.github_username,
		    avatar_url      = EXCLUDED.avatar_url,
		    updated_at      = now()`

	if _, err := p.pool.Exec(ctx, q, u.ID, u.GithubUsername, u.AvatarURL); err != nil {
		return fmt.Errorf("upsert user %s: %w", u.ID, err)
	}
	return nil
}
