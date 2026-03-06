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
	WriteHashes(context.Context, Input) (map[string]string, error)
}

type Default struct{}

func NewDefault() *Default { return &Default{} }

func (n *Default) WriteHashes(_ context.Context, in Input) (map[string]string, error) {
	sort.Strings(in.Files)
	if err := os.MkdirAll(filepath.Dir(in.OutputPath), 0o755); err != nil {
		return nil, err
	}
	f, err := os.Create(in.OutputPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	hashes := map[string]string{}
	for _, path := range in.Files {
		h, err := hashFile(path)
		if err != nil {
			return nil, err
		}
		base := filepath.Base(path)
		hashes[base] = h
		if _, err := fmt.Fprintf(f, "SHA256(%s)=%s\n", base, h); err != nil {
			return nil, err
		}
	}
	h, err := hashFile(in.OutputPath)
	if err == nil {
		hashes[filepath.Base(in.OutputPath)] = h
	}
	return hashes, nil
}

type Noop struct{}

func NewNoop() *Noop { return &Noop{} }

func (n *Noop) WriteHashes(ctx context.Context, in Input) (map[string]string, error) {
	return NewDefault().WriteHashes(ctx, in)
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
