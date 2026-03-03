package capture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	InputPCAPPath string
}

type Output struct {
	Host     contracts.HostInfo
	Metadata contracts.CaptureMetadata
}

type Module interface {
	Run(context.Context, Input) (Output, error)
}

type Default struct{}

func NewDefault() *Default { return &Default{} }

func (n *Default) Run(_ context.Context, in Input) (Output, error) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "UNKNOWN"
	}
	if in.InterfaceName == "" {
		in.InterfaceName = "unspecified"
	}
	if err := os.MkdirAll(filepath.Dir(in.PCAPPath), 0o755); err != nil {
		return Output{}, err
	}

	if in.InputPCAPPath != "" {
		src, err := os.ReadFile(in.InputPCAPPath)
		if err != nil {
			return Output{}, fmt.Errorf("read input pcap: %w", err)
		}
		if in.MaxBytes > 0 && int64(len(src)) > in.MaxBytes {
			src = src[:in.MaxBytes]
		}
		if err := os.WriteFile(in.PCAPPath, src, 0o644); err != nil {
			return Output{}, err
		}
	} else {
		if runtime.GOOS != "windows" {
			return Output{}, fmt.Errorf("live capture requires Windows+Npcap; provide --input-pcap for offline analysis")
		}
		if err := os.WriteFile(in.PCAPPath, []byte{}, 0o644); err != nil {
			return Output{}, err
		}
	}

	now := time.Now().UTC()
	end := now.Add(in.Duration)
	if in.Duration <= 0 {
		end = now
	}
	fi, _ := os.Stat(in.PCAPPath)
	pktCount := int64(0)
	if fi != nil && fi.Size() > 24 {
		pktCount = 1
	}

	return Output{
		Host: contracts.HostInfo{
			Hostname:         hostname,
			OSVersion:        runtime.GOOS,
			Architecture:     runtime.GOARCH,
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
			EndTimeUTC:      end,
			DurationSeconds: int(end.Sub(now).Seconds()),
			Interface:       in.InterfaceName,
			PacketCount:     pktCount,
			PCAPFile:        "original_capture.pcap",
			EndTimeUTC:      now.Add(in.Duration),
			DurationSeconds: int(in.Duration.Seconds()),
			Interface:       in.InterfaceName,
			PacketCount:     0,
			PCAPFile:        in.PCAPPath,
		},
	}, nil
}
