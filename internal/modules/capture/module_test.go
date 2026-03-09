package capture

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateInterfaceNameEmptyFails(t *testing.T) {
	_, err := ValidateInterfaceName("")
	if err == nil {
		t.Fatal("expected error for empty interface")
	}
	if !strings.Contains(err.Error(), "requires --interface") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFindInterfaceByNameNotFound(t *testing.T) {
	_, err := findInterfaceByName("Ethernet 9", []InterfaceInfo{{Name: "Ethernet 1", Description: "Intel"}, {Name: "Wi-Fi"}})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "not found") || !strings.Contains(err.Error(), "Ethernet 1") {
		t.Fatalf("expected useful not-found error, got: %v", err)
	}
}

func TestRunOfflinePCAPPath(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src.pcap")
	dst := filepath.Join(tmp, "out", "capture.pcap")
	writeTinyPCAP(t, src)

	out, err := NewDefault().Run(context.Background(), Input{
		PCAPPath:      dst,
		InputPCAPPath: src,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Metadata.PCAPFile != dst {
		t.Fatalf("pcap file mismatch: %s", out.Metadata.PCAPFile)
	}
	if out.Host.PrimaryInterface != "" {
		t.Fatalf("expected no primary interface in offline mode, got %q", out.Host.PrimaryInterface)
	}
	if out.Metadata.Interface != "" {
		t.Fatalf("expected empty capture interface in offline mode, got %q", out.Metadata.Interface)
	}
	if out.Metadata.EndTimeUTC.Before(out.Metadata.StartTimeUTC) {
		t.Fatalf("invalid timing: %s before %s", out.Metadata.EndTimeUTC, out.Metadata.StartTimeUTC)
	}
}

func TestRunLiveCaptureEmptyInterfaceFailsBeforeCapture(t *testing.T) {
	tmp := t.TempDir()
	_, err := NewDefault().Run(context.Background(), Input{
		InterfaceName: "",
		Duration:      5 * time.Second,
		PCAPPath:      filepath.Join(tmp, "capture.pcap"),
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "requires --interface") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func writeTinyPCAP(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gh := make([]byte, 24)
	copy(gh[:4], []byte{0xd4, 0xc3, 0xb2, 0xa1})
	binary.LittleEndian.PutUint16(gh[4:6], 2)
	binary.LittleEndian.PutUint16(gh[6:8], 4)
	binary.LittleEndian.PutUint32(gh[16:20], 65535)
	if _, err := f.Write(gh); err != nil {
		t.Fatal(err)
	}
	ph := make([]byte, 16)
	binary.LittleEndian.PutUint32(ph[0:4], uint32(time.Now().Unix()))
	binary.LittleEndian.PutUint32(ph[8:12], 1)
	binary.LittleEndian.PutUint32(ph[12:16], 1)
	if _, err := f.Write(ph); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0x00}); err != nil {
		t.Fatal(err)
	}
}
