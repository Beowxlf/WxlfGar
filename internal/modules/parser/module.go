package parser

import (
	"context"

	"github.com/wxlfgar/wulfgar/internal/contracts"
)

type Input struct{ PCAPPath string }

type Output struct{ Packets []contracts.ParsedPacket }

type Module interface {
	Parse(context.Context, Input) (Output, error)
}

type Noop struct{}

func NewNoop() *Noop { return &Noop{} }

func (n *Noop) Parse(_ context.Context, _ Input) (Output, error) { return Output{}, nil }
