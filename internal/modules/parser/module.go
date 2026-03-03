package parser

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/wxlfgar/wulfgar/internal/contracts"
)

const maxPacketBytes uint32 = 10 * 1024 * 1024

type Input struct{ PCAPPath string }

type Output struct{ Packets []contracts.ParsedPacket }

type Module interface {
	Parse(context.Context, Input) (Output, error)
}

type Default struct{}

func NewDefault() *Default { return &Default{} }

type pcapHeader struct {
	endian  binary.ByteOrder
	ns      bool
	snapLen uint32
}

func (n *Default) Parse(ctx context.Context, in Input) (Output, error) {
	f, err := os.Open(in.PCAPPath)
	if err != nil {
		return Output{}, err
	}
	defer f.Close()

	h, err := readGlobalHeader(f)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return Output{}, nil
		}
		return Output{}, err
	}

	packets := []contracts.ParsedPacket{}
	for {
		if err := ctx.Err(); err != nil {
			return Output{}, err
		}
		var ph [16]byte
		if _, err := io.ReadFull(f, ph[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return Output{}, err
		}
		tsSec := h.endian.Uint32(ph[0:4])
		tsFrac := h.endian.Uint32(ph[4:8])
		incl := h.endian.Uint32(ph[8:12])
		if incl == 0 {
			continue
		}
		if h.snapLen > 0 && incl > h.snapLen {
			if _, err := io.CopyN(io.Discard, f, int64(incl)); err != nil {
				return Output{}, err
			}
			continue
		}
		if incl > maxPacketBytes {
			if _, err := io.CopyN(io.Discard, f, int64(incl)); err != nil {
				return Output{}, err
			}
			continue
		}
		data := make([]byte, incl)
		if _, err := io.ReadFull(f, data); err != nil {
			return Output{}, err
		}
		t := time.Unix(int64(tsSec), fracToNanos(tsFrac, h.ns))
		parsed := parseFrame(data)
		parsed.Timestamp = t.UTC()
		packets = append(packets, parsed)
	}
	return Output{Packets: packets}, nil
}

func readGlobalHeader(r io.Reader) (pcapHeader, error) {
	var gh [24]byte
	if _, err := io.ReadFull(r, gh[:]); err != nil {
		return pcapHeader{}, err
	}
	magic := gh[0:4]
	h := pcapHeader{}
	switch {
	case bytes.Equal(magic, []byte{0xd4, 0xc3, 0xb2, 0xa1}):
		h.endian, h.ns = binary.LittleEndian, false
	case bytes.Equal(magic, []byte{0xa1, 0xb2, 0xc3, 0xd4}):
		h.endian, h.ns = binary.BigEndian, false
	case bytes.Equal(magic, []byte{0x4d, 0x3c, 0xb2, 0xa1}):
		h.endian, h.ns = binary.LittleEndian, true
	case bytes.Equal(magic, []byte{0xa1, 0xb2, 0x3c, 0x4d}):
		h.endian, h.ns = binary.BigEndian, true
	default:
		return pcapHeader{}, fmt.Errorf("unsupported pcap magic")
	}
	h.snapLen = h.endian.Uint32(gh[16:20])
	return h, nil
}

func fracToNanos(v uint32, ns bool) int64 {
	if ns {
		return int64(v)
	}
	return int64(v) * 1000
}

func parseFrame(b []byte) contracts.ParsedPacket {
	p := contracts.ParsedPacket{Protocol: "OTHER"}
	if len(b) < 14 {
		return p
	}
	etherType := binary.BigEndian.Uint16(b[12:14])
	if etherType != 0x0800 || len(b) < 34 {
		return p
	}
	ip := b[14:]
	ihl := int(ip[0]&0x0f) * 4
	if len(ip) < ihl || ihl < 20 {
		return p
	}
	proto := ip[9]
	p.SourceIP = fmt.Sprintf("%d.%d.%d.%d", ip[12], ip[13], ip[14], ip[15])
	p.DestinationIP = fmt.Sprintf("%d.%d.%d.%d", ip[16], ip[17], ip[18], ip[19])
	l4 := ip[ihl:]

	switch proto {
	case 6:
		if len(l4) < 20 {
			return p
		}
		p.Protocol = "TCP"
		p.SourcePort = binary.BigEndian.Uint16(l4[0:2])
		p.DestPort = binary.BigEndian.Uint16(l4[2:4])
		flags := l4[13]
		syn := flags&0x02 > 0
		ack := flags&0x10 > 0
		rst := flags&0x04 > 0
		p.Summary = fmt.Sprintf("tcp syn=%t ack=%t rst=%t", syn, ack, rst)
	case 17:
		if len(l4) < 8 {
			return p
		}
		p.Protocol = "UDP"
		p.SourcePort = binary.BigEndian.Uint16(l4[0:2])
		p.DestPort = binary.BigEndian.Uint16(l4[2:4])
		payload := l4[8:]
		if p.SourcePort == 53 || p.DestPort == 53 {
			p.Protocol = "DNS"
			p.Summary = dnsSummary(payload)
		}
		if p.SourcePort == 67 || p.SourcePort == 68 || p.DestPort == 67 || p.DestPort == 68 {
			p.Protocol = "DHCP"
			p.Summary = dhcpSummary(payload)
		}
	case 1:
		if len(l4) < 2 {
			return p
		}
		p.Protocol = "ICMP"
		p.Summary = fmt.Sprintf("icmp type=%d code=%d", l4[0], l4[1])
	}
	return p
}

func dnsSummary(payload []byte) string {
	if len(payload) < 4 {
		return "dns malformed"
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	rcode := flags & 0x000f
	qr := (flags & 0x8000) > 0
	rcodeName := map[uint16]string{0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}[rcode]
	if rcodeName == "" {
		rcodeName = fmt.Sprintf("CODE_%d", rcode)
	}
	return fmt.Sprintf("dns qr=%t rcode=%s", qr, rcodeName)
}

func dhcpSummary(payload []byte) string {
	if len(payload) < 240 {
		return "dhcp malformed"
	}
	xid := binary.BigEndian.Uint32(payload[4:8])
	msgType := byte(0)
	for i := 240; i < len(payload); {
		opt := payload[i]
		if opt == 0xff {
			break
		}
		if opt == 0 {
			i++
			continue
		}
		if i+1 >= len(payload) {
			break
		}
		l := int(payload[i+1])
		if i+2+l > len(payload) {
			break
		}
		if opt == 53 && l > 0 {
			msgType = payload[i+2]
			break
		}
		i += 2 + l
	}
	return fmt.Sprintf("dhcp xid=%d msgtype=%d", xid, msgType)
}
