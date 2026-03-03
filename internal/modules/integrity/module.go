package integrity

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

type Input struct {
	Files      []string
	OutputPath string
}

type Module interface {
	WriteHashes(context.Context, Input) error
}

type Noop struct{}

func NewNoop() *Noop { return &Noop{} }

func (n *Noop) WriteHashes(_ context.Context, in Input) error {
	sort.Strings(in.Files)
	if err := os.MkdirAll(filepath.Dir(in.OutputPath), 0o755); err != nil {
		return err
	}
	f, err := os.Create(in.OutputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, path := range in.Files {
		h, err := hashFile(path)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(f, "SHA256(%s)=%s\n", filepath.Base(path), h); err != nil {
			return err
		}
	}
	return nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
