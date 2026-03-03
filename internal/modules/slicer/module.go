package slicer

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
	out := Output{Events: in.Events}
	src, err := os.Open(in.PCAPPath)
	if err != nil {
		return Output{}, err
	}
	defer src.Close()

	for idx, event := range out.Events {
		name := fmt.Sprintf("%s_event_%d.pcap", normalizeProtocol(event.Protocol), idx+1)
		full := filepath.Join(in.SlicesPath, name)
		if err := copyFile(src, full); err != nil {
			return Output{}, err
		}
		if _, err := src.Seek(0, io.SeekStart); err != nil {
			return Output{}, err
		}
		out.Events[idx].SliceFile = name
		out.Paths = append(out.Paths, full)
		out.Artifacts = append(out.Artifacts, contracts.ArtifactEntry{FileName: filepath.ToSlash(filepath.Join("slices", name)), Type: "pcap_slice"})
	}
	return out, nil
}

func copyFile(src *os.File, dstPath string) error {
	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
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
