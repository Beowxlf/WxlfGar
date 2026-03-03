package detection

import (
	"context"

	"github.com/wxlfgar/wulfgar/internal/contracts"
)

type Input struct{ Packets []contracts.ParsedPacket }

type Output struct {
	Events  []contracts.Event
	Metrics contracts.Metrics
}

type Module interface {
	Detect(context.Context, Input) (Output, error)
}

type Noop struct{}

func NewNoop() *Noop { return &Noop{} }

func (n *Noop) Detect(_ context.Context, _ Input) (Output, error) { return Output{}, nil }
