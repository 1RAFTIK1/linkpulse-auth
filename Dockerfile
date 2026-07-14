# Multi-stage, тот же паттерн, что в остальных сервисах.
# Контекст сборки — родительская папка (replace на ../linkpulse-contracts):
#   docker build -f linkpulse-auth/Dockerfile .
FROM golang:1.26-alpine AS build

WORKDIR /src

COPY linkpulse-contracts/ ../linkpulse-contracts/
COPY linkpulse-auth/go.mod linkpulse-auth/go.sum ./
RUN go mod download

COPY linkpulse-auth/ .
# Только сервис; dev-утилита devtoken в образ не собирается.
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/auth ./cmd/auth

FROM alpine:3.22

RUN adduser -D -u 10001 app
USER app

COPY --from=build /out/auth /usr/local/bin/auth
COPY --from=build /src/migrations /migrations

EXPOSE 8083 50052
ENTRYPOINT ["auth"]
