package slicer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

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

type Default struct{}

func NewDefault() *Default { return &Default{} }

func (n *Default) Slice(_ context.Context, in Input) (Output, error) {
	if err := os.MkdirAll(in.SlicesPath, 0o755); err != nil {
		return Output{}, err
	}

	capture, err := readPCAP(in.PCAPPath)
	useWindowed := err == nil
	fallbackReason := ""
	if err != nil {
		fallbackReason = err.Error()
	}

	out := Output{Events: in.Events}
	for idx, event := range out.Events {
		name := fmt.Sprintf("%s_event_%d.pcap", normalizeProtocol(event.Protocol), idx+1)
		full := filepath.Join(in.SlicesPath, name)
		start := event.TimestampUTC.Add(-60 * time.Second)
		end := event.TimestampUTC.Add(60 * time.Second)
		if useWindowed {
			if err := writeSlice(full, capture, start, end); err != nil {
				return Output{}, err
			}
		} else {
			if err := copyRawPCAP(in.PCAPPath, full); err != nil {
				return Output{}, err
			}
			if fallbackReason == "" {
				fallbackReason = "windowed slicing unavailable"
			}
			out.Events[idx].Description = fmt.Sprintf("%s (slice fallback: raw copy of original capture; reason: %s)", strings.TrimSpace(out.Events[idx].Description), fallbackReason)
		}
		out.Events[idx].SliceFile = name
		out.Paths = append(out.Paths, full)
		artifactType := "pcap_slice"
		if !useWindowed {
			artifactType = "pcap_slice_fallback_raw_copy"
		}
		out.Artifacts = append(out.Artifacts, contracts.ArtifactEntry{FileName: filepath.ToSlash(filepath.Join("slices", name)), Type: artifactType})
	}
	return out, nil
}

type pcapCapture struct {
	globalHeader []byte
	packets      []pcapPacket
}

type pcapPacket struct {
	timestamp time.Time
	header    [16]byte
	data      []byte
}

func readPCAP(path string) (pcapCapture, error) {
	f, err := os.Open(path)
	if err != nil {
		return pcapCapture{}, err
	}
	defer f.Close()

	var gh [24]byte
	if _, err := io.ReadFull(f, gh[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return pcapCapture{}, fmt.Errorf("pcap global header missing")
		}
		return pcapCapture{}, err
	}

	endian, ns, err := readGlobalHeaderEndian(gh[:4])
	if err != nil {
		return pcapCapture{}, err
	}

	out := pcapCapture{globalHeader: gh[:]}
	for {
		var ph [16]byte
		if _, err := io.ReadFull(f, ph[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return pcapCapture{}, err
		}
		incl := endian.Uint32(ph[8:12])
		if incl == 0 {
			continue
		}
		data := make([]byte, incl)
		if _, err := io.ReadFull(f, data); err != nil {
			return pcapCapture{}, err
		}
		tsSec := endian.Uint32(ph[0:4])
		tsFrac := endian.Uint32(ph[4:8])
		ts := time.Unix(int64(tsSec), fracToNanos(tsFrac, ns)).UTC()
		out.packets = append(out.packets, pcapPacket{timestamp: ts, header: ph, data: data})
	}
	return out, nil
}

func copyRawPCAP(srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}

func writeSlice(path string, cap pcapCapture, start, end time.Time) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(cap.globalHeader); err != nil {
		return err
	}
	for _, pkt := range cap.packets {
		if pkt.timestamp.Before(start) || pkt.timestamp.After(end) {
			continue
		}
		if _, err := f.Write(pkt.header[:]); err != nil {
			return err
		}
		if _, err := f.Write(pkt.data); err != nil {
			return err
		}
	}
	return nil
}

func readGlobalHeaderEndian(magic []byte) (binary.ByteOrder, bool, error) {
	m := binary.LittleEndian.Uint32(magic)
	switch m {
	case 0xa1b2c3d4:
		return binary.LittleEndian, false, nil
	case 0xd4c3b2a1:
		return binary.BigEndian, false, nil
	case 0xa1b23c4d:
		return binary.LittleEndian, true, nil
	case 0x4d3cb2a1:
		return binary.BigEndian, true, nil
	default:
		return nil, false, fmt.Errorf("unsupported pcap magic")
	}
}

func fracToNanos(v uint32, ns bool) int64 {
	if ns {
		return int64(v)
	}
	return int64(v) * 1000
}

func normalizeProtocol(protocol string) string {
	switch strings.ToUpper(protocol) {
	case "DNS":
		return "dns"
	case "ICMP":
		return "icmp"
	case "DHCP":
		return "dhcp"
	case "SMB":
		return "smb"
	default:
		return "tcp"
	}
}

type Noop struct{}

func NewNoop() *Noop { return &Noop{} }

func (n *Noop) Slice(ctx context.Context, in Input) (Output, error) {
	return NewDefault().Slice(ctx, in)
}
