package parser

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestParseSupportsLittleEndianMagic(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "x.pcap")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gh := make([]byte, 24)
	copy(gh[0:4], []byte{0xd4, 0xc3, 0xb2, 0xa1})
	binary.LittleEndian.PutUint16(gh[4:6], 2)
	binary.LittleEndian.PutUint16(gh[6:8], 4)
	binary.LittleEndian.PutUint32(gh[16:20], 65535)
	if _, err := f.Write(gh); err != nil {
		t.Fatal(err)
	}
	ph := make([]byte, 16)
	binary.LittleEndian.PutUint32(ph[8:12], 1)
	binary.LittleEndian.PutUint32(ph[12:16], 1)
	if _, err := f.Write(ph); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0x00}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := NewDefault().Parse(context.Background(), Input{PCAPPath: p})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(out.Packets))
	}
}
