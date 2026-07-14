// Package grpcapi — реализация auth.v1.AuthService.
package grpcapi

import (
	"context"
	"log/slog"

	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "github.com/1RAFTIK1/linkpulse-contracts/gen/go/auth/v1"

	"github.com/1RAFTIK1/linkpulse-auth/internal/token"
)

type Server struct {
	authv1.UnimplementedAuthServiceServer
	verifier *token.Verifier
	log      *slog.Logger
}

func NewServer(verifier *token.Verifier, log *slog.Logger) *Server {
	return &Server{verifier: verifier, log: log}
}

// ValidateToken проверяет внутренний JWT. Невалидный токен — это НЕ ошибка
// RPC, а валидный ответ {valid: false}: ошибки транспорта и «плохой токен» —
// разные ситуации для вызывающего сервиса.
func (s *Server) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	claims, err := s.verifier.Verify(req.GetToken())
	if err != nil {
		s.log.DebugContext(ctx, "токен отклонён", "error", err)
		return &authv1.ValidateTokenResponse{Valid: false}, nil
	}
	return &authv1.ValidateTokenResponse{
		Valid:          true,
		UserId:         claims.Subject,
		GithubUsername: claims.Username,
		ExpiresAt:      timestamppb.New(claims.ExpiresAt.Time),
	}, nil
}
