package detection

import (
	"context"
	"testing"
	"time"

	"github.com/wxlfgar/wulfgar/internal/contracts"
)

func TestDetectDNSAndTCP(t *testing.T) {
	m := NewDefault()
	now := time.Now().UTC()
	in := Input{Packets: []contracts.ParsedPacket{
		{Protocol: "DNS", Summary: "dns qr=true rcode=NXDOMAIN", Timestamp: now},
		{Protocol: "TCP", Summary: "tcp syn=true ack=false rst=false", SourceIP: "1.1.1.1", DestinationIP: "2.2.2.2", SourcePort: 1234, DestPort: 80, Timestamp: now},
		{Protocol: "TCP", Summary: "tcp syn=true ack=false rst=false", SourceIP: "1.1.1.1", DestinationIP: "2.2.2.2", SourcePort: 1234, DestPort: 80, Timestamp: now.Add(time.Second)},
		{Protocol: "ICMP", Summary: "icmp type=3 code=1", Timestamp: now},
	}}
	out, err := m.Detect(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if out.Metrics.DNS.NXDOMAINCount != 1 {
		t.Fatalf("expected NXDOMAIN count 1, got %d", out.Metrics.DNS.NXDOMAINCount)
	}
	if out.Metrics.TCP.SYNRetransmits != 1 {
		t.Fatalf("expected syn retransmits 1, got %d", out.Metrics.TCP.SYNRetransmits)
	}
	if out.Metrics.ICMP.DestinationUnreachable != 1 {
		t.Fatalf("expected icmp unreachable 1, got %d", out.Metrics.ICMP.DestinationUnreachable)
	}
}

func TestDetectDNSTimeoutAndDHCP(t *testing.T) {
	m := NewDefault()
	now := time.Now().UTC()
	in := Input{Packets: []contracts.ParsedPacket{
		{Protocol: "DNS", Summary: "dns qr=false rcode=NOERROR", SourceIP: "10.0.0.10", DestinationIP: "8.8.8.8", SourcePort: 50000, DestPort: 53, Timestamp: now},
		{Protocol: "DNS", Summary: "dns qr=false rcode=NOERROR", SourceIP: "10.0.0.10", DestinationIP: "8.8.8.8", SourcePort: 50000, DestPort: 53, Timestamp: now.Add(3 * time.Second)},
		{Protocol: "DHCP", Summary: "dhcp xid=1 msgtype=1", SourceIP: "0.0.0.0", Timestamp: now},
	}}
	out, err := m.Detect(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if out.Metrics.DNS.TimeoutCount != 1 {
		t.Fatalf("expected dns timeout count 1, got %d", out.Metrics.DNS.TimeoutCount)
	}
	if out.Metrics.DHCP.DiscoverWithoutOffer != 1 {
		t.Fatalf("expected dhcp discover without offer 1, got %d", out.Metrics.DHCP.DiscoverWithoutOffer)
	}
}
