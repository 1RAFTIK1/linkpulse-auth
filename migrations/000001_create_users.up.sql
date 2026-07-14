-- Пользователи, вошедшие через GitHub OAuth. id = числовой GitHub user id
-- строкой: он стабилен (login может меняться), и его же несёт JWT в sub.
CREATE TABLE users (
    id              TEXT PRIMARY KEY,
    github_username TEXT NOT NULL,
    avatar_url      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
