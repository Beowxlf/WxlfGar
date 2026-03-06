package slicer

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wxlfgar/wulfgar/internal/contracts"
)

func TestSliceUsesEventWindow(t *testing.T) {
	d := t.TempDir()
	pcap := filepath.Join(d, "in.pcap")
	writeTestPCAP(t, pcap, []int64{100, 130, 160, 250})

	eventTime := time.Unix(160, 0).UTC()
	out, err := NewDefault().Slice(context.Background(), Input{
		PCAPPath:   pcap,
		SlicesPath: filepath.Join(d, "slices"),
		Events: []contracts.Event{{
			EventID:       "dns_1",
			Protocol:      "DNS",
			TimestampUTC:  eventTime,
			IndicatorType: "NXDOMAIN",
			Description:   "x",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Paths) != 1 {
		t.Fatalf("expected one slice path, got %d", len(out.Paths))
	}
	count := countPackets(t, out.Paths[0])
	if count != 3 {
		t.Fatalf("expected 3 packets in +/-60s window, got %d", count)
	}
}

func writeTestPCAP(t *testing.T, path string, seconds []int64) {
	t.Helper()
	f, err := os.Create(path)
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

	for _, sec := range seconds {
		ph := make([]byte, 16)
		binary.LittleEndian.PutUint32(ph[0:4], uint32(sec))
		binary.LittleEndian.PutUint32(ph[8:12], 1)
		binary.LittleEndian.PutUint32(ph[12:16], 1)
		if _, err := f.Write(ph); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte{0x00}); err != nil {
			t.Fatal(err)
		}
	}
}

func countPackets(t *testing.T, pcapPath string) int {
	t.Helper()
	blob, err := os.ReadFile(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) < 24 {
		return 0
	}
	count := 0
	i := 24
	for i+16 <= len(blob) {
		incl := int(binary.LittleEndian.Uint32(blob[i+8 : i+12]))
		i += 16
		if incl <= 0 || i+incl > len(blob) {
			break
		}
		i += incl
		count++
	}
	return count
}
