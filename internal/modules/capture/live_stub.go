//go:build !windows

package capture

import (
	"context"
	"fmt"
	"runtime"
	"time"
)

type liveInput struct {
	InterfaceName string
	Duration      time.Duration
	MaxBytes      int64
	PCAPPath      string
}

type liveOutput struct {
	StartTimeUTC time.Time
	EndTimeUTC   time.Time
	PacketCount  int64
	SizeLimitHit bool
}

func listInterfaces() ([]InterfaceInfo, error) {
	return nil, fmt.Errorf("capture interface enumeration requires Windows+Npcap; current OS=%s", runtime.GOOS)
}

func runLiveCapture(_ context.Context, _ liveInput) (liveOutput, error) {
	return liveOutput{}, fmt.Errorf("live capture requires Windows+Npcap; use --input-pcap for offline analysis")
}
