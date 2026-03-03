package capture

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/wxlfgar/wulfgar/internal/contracts"
)

type Input struct {
	InterfaceName string
	Duration      time.Duration
	MaxBytes      int64
	PCAPPath      string
}

type Output struct {
	Host     contracts.HostInfo
	Metadata contracts.CaptureMetadata
}

type Module interface {
	Run(context.Context, Input) (Output, error)
}

type Noop struct{}

func NewNoop() *Noop { return &Noop{} }

func (n *Noop) Run(_ context.Context, in Input) (Output, error) {
	if err := os.MkdirAll(filepath.Dir(in.PCAPPath), 0o755); err != nil {
		return Output{}, err
	}
	if err := os.WriteFile(in.PCAPPath, []byte(""), 0o644); err != nil {
		return Output{}, err
	}
	now := time.Now().UTC()
	return Output{
		Host: contracts.HostInfo{
			Hostname:         "UNSET",
			OSVersion:        "Windows",
			Architecture:     "x64",
			PrimaryInterface: in.InterfaceName,
			InterfaceIP:      "0.0.0.0",
		},
		Metadata: contracts.CaptureMetadata{
			StartTimeUTC:    now,
			EndTimeUTC:      now.Add(in.Duration),
			DurationSeconds: int(in.Duration.Seconds()),
			Interface:       in.InterfaceName,
			PacketCount:     0,
			PCAPFile:        in.PCAPPath,
		},
	}, nil
}
