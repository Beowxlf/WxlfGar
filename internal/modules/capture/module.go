package capture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

type InterfaceInfo struct {
	Name        string
	CaptureName string
	Description string
}

type Module interface {
	Run(context.Context, Input) (Output, error)
}

type Default struct{}

func NewDefault() *Default { return &Default{} }

func ListInterfaces() ([]InterfaceInfo, error) {
	interfaces, err := listInterfaces()
	if err != nil {
		return nil, err
	}
	return interfaces, nil
}

func ValidateInterfaceName(interfaceName string) (InterfaceInfo, error) {
	trimmed := strings.TrimSpace(interfaceName)
	if trimmed == "" {
		return InterfaceInfo{}, fmt.Errorf("live capture requires --interface with a valid interface alias")
	}

	interfaces, err := listInterfaces()
	if err != nil {
		return InterfaceInfo{}, err
	}
	return findInterfaceByName(trimmed, interfaces)
}

func findInterfaceByName(name string, interfaces []InterfaceInfo) (InterfaceInfo, error) {
	lookup := strings.ToLower(name)
	for _, iface := range interfaces {
		if strings.ToLower(iface.Name) == lookup || strings.ToLower(iface.CaptureName) == lookup || strings.ToLower(iface.Description) == lookup {
			return iface, nil
		}
	}
	available := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Description == "" {
			available = append(available, iface.Name)
			continue
		}
		if iface.CaptureName != "" && iface.CaptureName != iface.Name {
			available = append(available, fmt.Sprintf("%s (%s) [capture device: %s]", iface.Name, iface.Description, iface.CaptureName))
			continue
		}
		available = append(available, fmt.Sprintf("%s (%s)", iface.Name, iface.Description))
	}
	if len(available) == 0 {
		return InterfaceInfo{}, fmt.Errorf("capture interface %q not found and no capture interfaces were discovered", name)
	}
	return InterfaceInfo{}, fmt.Errorf("capture interface %q not found; available interfaces: %s", name, strings.Join(available, ", "))
}

func (n *Default) Run(ctx context.Context, in Input) (Output, error) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "UNKNOWN"
	}
	if err := os.MkdirAll(filepath.Dir(in.PCAPPath), 0o755); err != nil {
		return Output{}, err
	}

	captureOut := contracts.CaptureMetadata{PCAPFile: in.PCAPPath}
	host := contracts.HostInfo{
		Hostname:     hostname,
		OSVersion:    runtime.GOOS,
		Architecture: runtime.GOARCH,
		InterfaceIP:  "0.0.0.0",
	}

	if in.InputPCAPPath != "" {
		src, err := os.ReadFile(in.InputPCAPPath)
		if err != nil {
			return Output{}, fmt.Errorf("read input pcap: %w", err)
		}
		if in.MaxBytes > 0 && int64(len(src)) > in.MaxBytes {
			src = src[:in.MaxBytes]
			captureOut.SizeLimitHit = true
		}
		start := time.Now().UTC()
		if err := os.WriteFile(in.PCAPPath, src, 0o644); err != nil {
			return Output{}, err
		}
		end := time.Now().UTC()
		captureOut.StartTimeUTC = start
		captureOut.EndTimeUTC = end
		captureOut.DurationSeconds = int(end.Sub(start).Seconds())
	} else {
		selectedInterface, err := ValidateInterfaceName(in.InterfaceName)
		if err != nil {
			return Output{}, err
		}
		host.PrimaryInterface = selectedInterface.Name
		captureOut.Interface = selectedInterface.Name
		if selectedInterface.CaptureName == "" {
			selectedInterface.CaptureName = selectedInterface.Name
		}

		liveOut, err := runLiveCapture(ctx, liveInput{
			InterfaceName: selectedInterface.CaptureName,
			Duration:      in.Duration,
			MaxBytes:      in.MaxBytes,
			PCAPPath:      in.PCAPPath,
		})
		if err != nil {
			return Output{}, err
		}
		captureOut.StartTimeUTC = liveOut.StartTimeUTC
		captureOut.EndTimeUTC = liveOut.EndTimeUTC
		captureOut.DurationSeconds = int(liveOut.EndTimeUTC.Sub(liveOut.StartTimeUTC).Seconds())
		captureOut.PacketCount = liveOut.PacketCount
		captureOut.SizeLimitHit = liveOut.SizeLimitHit
	}

	if captureOut.Interface == "" {
		captureOut.Interface = host.PrimaryInterface
	}
	if in.InputPCAPPath == "" {
		if fi, err := os.Stat(in.PCAPPath); err == nil && fi.Size() <= 24 {
			return Output{}, fmt.Errorf("capture output %s is empty or header-only (%d bytes)", in.PCAPPath, fi.Size())
		}
	}

	return Output{Host: host, Metadata: captureOut}, nil
}

type Noop struct{}

func NewNoop() *Noop { return &Noop{} }

func (n *Noop) Run(ctx context.Context, in Input) (Output, error) {
	return NewDefault().Run(ctx, in)
}
