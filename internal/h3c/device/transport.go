package device

import (
	"context"
	"time"
)

type Auth struct {
	Username string
	Password []byte
}

func (a *Auth) Zero() {
	for i := range a.Password { a.Password[i] = 0 }
}

type DialConfig struct {
	Addr           string
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
}

type Transport interface {
	Connect(ctx context.Context, cfg DialConfig) error
	Send(ctx context.Context, data []byte) error
	ReadUntil(ctx context.Context, patterns []string, deadline time.Time) (string, int, error)
	Close() error
}
