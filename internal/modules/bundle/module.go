package bundle

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type PrepareInput struct{ OutputRoot string }

type Module interface {
	PrepareLayout(context.Context, PrepareInput) (string, error)
	Compress(context.Context, string) (string, error)
}

type Noop struct{}

func NewNoop() *Noop { return &Noop{} }

func (n *Noop) PrepareLayout(_ context.Context, in PrepareInput) (string, error) {
	hostname := "HOST"
	ts := time.Now().UTC().Format("20060102_150405")
	bundleName := fmt.Sprintf("Wulfgar_%s_%s", hostname, ts)
	bundlePath := filepath.Join(in.OutputRoot, bundleName)
	for _, dir := range []string{"", "triage", "slices"} {
		if err := os.MkdirAll(filepath.Join(bundlePath, dir), 0o755); err != nil {
			return "", err
		}
	}
	return bundlePath, nil
}

func (n *Noop) Compress(_ context.Context, bundlePath string) (string, error) {
	zipPath := bundlePath + ".zip"
	out, err := os.Create(zipPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	zw := zip.NewWriter(out)
	defer zw.Close()

	err = filepath.Walk(bundlePath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		rel := strings.TrimPrefix(path, bundlePath+string(os.PathSeparator))
		w, err := zw.Create(rel)
		if err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(w, in)
		return err
	})
	if err != nil {
		return "", err
	}
	return zipPath, nil
}
