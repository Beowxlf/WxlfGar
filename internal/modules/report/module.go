package report

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/wxlfgar/wulfgar/internal/contracts"
)

type Input struct {
	BundlePath string
	Machine    contracts.MachineReport
}

type Output struct{ Files []string }

type Module interface {
	Generate(context.Context, Input) (Output, error)
}

type Noop struct{}

func NewNoop() *Noop { return &Noop{} }

func (n *Noop) Generate(_ context.Context, in Input) (Output, error) {
	machinePath := filepath.Join(in.BundlePath, "machine.json")
	summaryPath := filepath.Join(in.BundlePath, "summary.txt")

	blob, err := json.MarshalIndent(in.Machine, "", "  ")
	if err != nil {
		return Output{}, err
	}
	if err := os.WriteFile(machinePath, blob, 0o644); err != nil {
		return Output{}, err
	}

	summary := []string{
		"Wulfgar Summary",
		fmt.Sprintf("Interface: %s", in.Machine.Capture.Interface),
		fmt.Sprintf("DurationSeconds: %d", in.Machine.Capture.DurationSeconds),
		fmt.Sprintf("Events: %d", len(in.Machine.Events)),
	}
	sort.Strings(summary)
	if err := os.WriteFile(summaryPath, []byte(strings.Join(summary, "\n")+"\n"), 0o644); err != nil {
		return Output{}, err
	}
	return Output{Files: []string{machinePath, summaryPath, filepath.Join(in.BundlePath, "original_capture.pcap")}}, nil
}
