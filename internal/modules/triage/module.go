package triage

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/wxlfgar/wulfgar/internal/contracts"
)

var AllowedCommands = []string{
	"nslookup google.com",
	"ipconfig /all",
	"route print",
	"arp -a",
	"netsh interface show interface",
}

type Input struct {
	Events       []contracts.Event
	TriagePath   string
	StartedAtUTC time.Time
}

type Output struct {
	Paths     []string
	Artifacts []contracts.ArtifactEntry
}

type Module interface {
	Run(context.Context, Input) (Output, error)
}

type Default struct{}

func NewDefault() *Default { return &Default{} }

func (n *Default) Run(_ context.Context, in Input) (Output, error) {
	if err := os.MkdirAll(in.TriagePath, 0o755); err != nil {
		return Output{}, err
	}
	files := []struct{ name, cmd string }{
		{"nslookup.txt", AllowedCommands[0]},
		{"ipconfig.txt", AllowedCommands[1]},
		{"route.txt", AllowedCommands[2]},
		{"arp.txt", AllowedCommands[3]},
		{"netsh_interface.txt", AllowedCommands[4]},
	}
	out := Output{}
	for _, item := range files {
		path := filepath.Join(in.TriagePath, item.name)
		exitCode, output := runCommand(item.cmd)
		body := fmt.Sprintf("command=%s\ntimestamp_utc=%s\nexit_code=%d\noutput=%s\n", item.cmd, in.StartedAtUTC.Format(time.RFC3339), exitCode, output)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			return Output{}, err
		}
		out.Paths = append(out.Paths, path)
		out.Artifacts = append(out.Artifacts, contracts.ArtifactEntry{FileName: filepath.ToSlash(filepath.Join("triage", item.name)), Type: "triage_output"})
	}
	return out, nil
}

func runCommand(cmdline string) (int, string) {
	if runtime.GOOS != "windows" {
		return 0, "stub (non-windows platform)"
	}
	cmd := exec.Command("cmd", "/C", cmdline)
	b, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(b)
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), string(b)
	}
	return 1, err.Error()
}

type Noop struct{}

func NewNoop() *Noop { return &Noop{} }

func (n *Noop) Run(ctx context.Context, in Input) (Output, error) {
	return NewDefault().Run(ctx, in)
}
