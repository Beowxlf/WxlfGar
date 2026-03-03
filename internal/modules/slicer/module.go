package slicer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/wxlfgar/wulfgar/internal/contracts"
)

type Input struct {
	PCAPPath   string
	Events     []contracts.Event
	SlicesPath string
}

type Output struct {
	Events    []contracts.Event
	Paths     []string
	Artifacts []contracts.ArtifactEntry
}

type Module interface {
	Slice(context.Context, Input) (Output, error)
}

type Noop struct{}

func NewNoop() *Noop { return &Noop{} }

func (n *Noop) Slice(_ context.Context, in Input) (Output, error) {
	if err := os.MkdirAll(in.SlicesPath, 0o755); err != nil {
		return Output{}, err
	}
	out := Output{Events: in.Events}
	for idx, event := range out.Events {
		name := fmt.Sprintf("%s_event_%d.pcap", normalizeProtocol(event.Protocol), idx+1)
		full := filepath.Join(in.SlicesPath, name)
		if err := os.WriteFile(full, []byte(""), 0o644); err != nil {
			return Output{}, err
		}
		out.Events[idx].SliceFile = name
		out.Paths = append(out.Paths, full)
		out.Artifacts = append(out.Artifacts, contracts.ArtifactEntry{FileName: filepath.ToSlash(filepath.Join("slices", name)), Type: "pcap_slice"})
	}
	return out, nil
}

func normalizeProtocol(protocol string) string {
	switch protocol {
	case "DNS", "dns":
		return "dns"
	case "ICMP", "icmp":
		return "icmp"
	default:
		return "tcp"
	}
}
