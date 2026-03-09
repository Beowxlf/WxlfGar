//go:build windows

package capture

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
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
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, wrapPCAPInitError(err)
	}
	out := make([]InterfaceInfo, 0, len(devs))
	for _, dev := range devs {
		out = append(out, InterfaceInfo{Name: dev.Name, Description: dev.Description})
	}
	return out, nil
}

func runLiveCapture(ctx context.Context, in liveInput) (liveOutput, error) {
	if in.Duration <= 0 {
		return liveOutput{}, fmt.Errorf("live capture requires --duration > 0")
	}

	handle, err := pcap.OpenLive(in.InterfaceName, 65535, true, 500*time.Millisecond)
	if err != nil {
		return liveOutput{}, wrapOpenLiveError(in.InterfaceName, err)
	}
	defer handle.Close()

	f, err := os.Create(in.PCAPPath)
	if err != nil {
		return liveOutput{}, err
	}
	defer f.Close()

	writer := pcapgo.NewWriter(f)
	if err := writer.WriteFileHeader(65535, handle.LinkType()); err != nil {
		return liveOutput{}, fmt.Errorf("write pcap header: %w", err)
	}

	start := time.Now().UTC()
	deadline := start.Add(in.Duration)
	var packetCount int64
	var writtenBytes int64
	sizeLimitHit := false

	for {
		if ctx.Err() != nil {
			return liveOutput{}, ctx.Err()
		}
		if time.Now().UTC().After(deadline) {
			break
		}

		data, ci, err := handle.ReadPacketData()
		if err != nil {
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			return liveOutput{}, fmt.Errorf("read packet: %w", err)
		}
		packetCount++

		if in.MaxBytes > 0 && writtenBytes+int64(len(data)) > in.MaxBytes {
			// TODO(phase1): bytes limiting currently caps written payload bytes only.
			// Header bytes are not included in the limit, but this still prevents
			// unbounded growth while preserving timed capture semantics.
			sizeLimitHit = true
			continue
		}
		if err := writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:      ci.Timestamp,
			CaptureLength:  ci.CaptureLength,
			Length:         ci.Length,
			InterfaceIndex: ci.InterfaceIndex,
		}, data); err != nil {
			return liveOutput{}, fmt.Errorf("write packet: %w", err)
		}
		writtenBytes += int64(len(data))
	}

	end := time.Now().UTC()
	return liveOutput{StartTimeUTC: start, EndTimeUTC: end, PacketCount: packetCount, SizeLimitHit: sizeLimitHit}, nil
}

func wrapPCAPInitError(err error) error {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "wpcap") || strings.Contains(msg, "npcap") {
		return fmt.Errorf("Npcap not available; install Npcap in WinPcap API-compatible mode: %w", err)
	}
	return fmt.Errorf("failed to enumerate capture interfaces: %w", err)
}

func wrapOpenLiveError(interfaceName string, err error) error {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "wpcap") || strings.Contains(msg, "npcap") {
		return fmt.Errorf("Npcap not available; cannot open interface %q: %w", interfaceName, err)
	}
	if strings.Contains(msg, "permission") || strings.Contains(msg, "access is denied") {
		return fmt.Errorf("insufficient privileges to capture on %q; run as administrator: %w", interfaceName, err)
	}
	return fmt.Errorf("failed to open capture interface %q: %w", interfaceName, err)
}
