// Auth service — GitHub OAuth, выпуск внутренних JWT (RS256), JWKS,
// gRPC ValidateToken для остальных сервисов.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"

	authv1 "github.com/1RAFTIK1/linkpulse-contracts/gen/go/auth/v1"

	"github.com/1RAFTIK1/linkpulse-auth/internal/config"
	"github.com/1RAFTIK1/linkpulse-auth/internal/githubapi"
	"github.com/1RAFTIK1/linkpulse-auth/internal/grpcapi"
	"github.com/1RAFTIK1/linkpulse-auth/internal/httpapi"
	"github.com/1RAFTIK1/linkpulse-auth/internal/storage"
	"github.com/1RAFTIK1/linkpulse-auth/internal/token"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if err := run(log); err != nil {
		log.Error("сервис завершился с ошибкой", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	key, err := token.LoadPrivateKey(cfg.JWTPrivateKeyPath)
	if err != nil {
		return err
	}
	issuer := token.NewIssuer(key, cfg.TokenTTL)
	verifier := token.NewVerifier(&key.PublicKey)

	initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	store, err := storage.NewPostgres(initCtx, cfg.PostgresDSN)
	if err != nil {
		return err
	}
	defer store.Close()

	gh := githubapi.New(cfg.GithubClientID, cfg.GithubClientSecret, cfg.OAuthRedirectURL)
	handlers := httpapi.NewHandlers(gh, store, issuer, cfg.FrontendURL, cfg.SecureCookies, log)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/github/login", handlers.Login)
	mux.HandleFunc("GET /auth/github/callback", handlers.Callback)
	mux.HandleFunc("GET /.well-known/jwks.json", handlers.JWKS)
	mux.HandleFunc("GET /healthz", handlers.Healthz)

	httpSrv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	grpcSrv := grpc.NewServer()
	authv1.RegisterAuthServiceServer(grpcSrv, grpcapi.NewServer(verifier, log))

	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", cfg.GRPCAddr)
	if err != nil {
		return fmt.Errorf("listen grpc: %w", err)
	}

	errCh := make(chan error, 2)
	go func() {
		log.Info("http сервер запущен", "addr", cfg.HTTPAddr)
		if err := httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		log.Info("grpc сервер запущен", "addr", cfg.GRPCAddr)
		if err := grpcSrv.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		grpcSrv.Stop()
		return err
	case <-ctx.Done():
	}

	// Обычный HTTP graceful shutdown, ничего специфичного (спека §11).
	log.Info("получен сигнал, останавливаемся", "timeout", cfg.ShutdownTimeout)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() { grpcSrv.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-shutdownCtx.Done():
		grpcSrv.Stop()
	}
	log.Info("сервис остановлен корректно")
	return nil
}
