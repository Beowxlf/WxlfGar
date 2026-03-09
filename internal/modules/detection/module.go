package detection

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/wxlfgar/wulfgar/internal/contracts"
)

type Input struct{ Packets []contracts.ParsedPacket }

type Output struct {
	Events  []contracts.Event
	Metrics contracts.Metrics
}

type Module interface {
	Detect(context.Context, Input) (Output, error)
}

type Default struct{}

func NewDefault() *Default { return &Default{} }

func (n *Default) Detect(_ context.Context, in Input) (Output, error) {
	out := Output{}
	idx := 0
	synSeen := map[string]time.Time{}
	dhcpState := map[string]byte{}
	dhcpLastSeen := map[string]time.Time{}
	dnsPending := map[string]time.Time{}
	dnsTimeoutCount := map[string]int{}
	dnsTimeoutLastSeen := map[string]time.Time{}

	for _, p := range in.Packets {
		s := strings.ToLower(p.Summary)
		switch p.Protocol {
		case "DNS":
			flow := fmt.Sprintf("%s:%d>%s:%d", p.SourceIP, p.SourcePort, p.DestinationIP, p.DestPort)
			if strings.Contains(s, "qr=false") {
				if first, ok := dnsPending[flow]; ok {
					if p.Timestamp.Sub(first) >= 2*time.Second {
						dnsTimeoutCount[flow]++
						dnsTimeoutLastSeen[flow] = p.Timestamp
						dnsPending[flow] = p.Timestamp
					}
				} else {
					dnsPending[flow] = p.Timestamp
					dnsTimeoutLastSeen[flow] = p.Timestamp
				}
			}
			if strings.Contains(s, "qr=true") {
				reverseFlow := fmt.Sprintf("%s:%d>%s:%d", p.DestinationIP, p.DestPort, p.SourceIP, p.SourcePort)
				delete(dnsPending, reverseFlow)
			}
			if strings.Contains(s, "nxdomain") {
				out.Metrics.DNS.NXDOMAINCount++
				idx++
				out.Events = append(out.Events, mkEvent(idx, "DNS", "NXDOMAIN", p, "DNS NXDOMAIN response observed"))
			}
			if strings.Contains(s, "servfail") {
				out.Metrics.DNS.SERVFAILCount++
				idx++
				out.Events = append(out.Events, mkEvent(idx, "DNS", "SERVFAIL", p, "DNS SERVFAIL response observed"))
			}
			if strings.Contains(s, "refused") {
				idx++
				out.Events = append(out.Events, mkEvent(idx, "DNS", "REFUSED", p, "DNS REFUSED response observed"))
			}
		case "TCP":
			key := fmt.Sprintf("%s:%d>%s:%d", p.SourceIP, p.SourcePort, p.DestinationIP, p.DestPort)
			if strings.Contains(s, "syn=true") && !strings.Contains(s, "ack=true") {
				if first, ok := synSeen[key]; ok && p.Timestamp.Sub(first) <= 3*time.Second {
					out.Metrics.TCP.SYNRetransmits++
					idx++
					e := mkEvent(idx, "TCP", "SYN_RETRANSMIT", p, "Repeated TCP SYN observed")
					e.RetransmitCount = 1
					out.Events = append(out.Events, e)
				}
				synSeen[key] = p.Timestamp
			}
			if strings.Contains(s, "rst=true") {
				out.Metrics.TCP.ConnectionReset++
				idx++
				out.Events = append(out.Events, mkEvent(idx, "TCP", "CONNECTION_RESET", p, "TCP reset observed"))
			}
			if p.DestPort == 445 || p.SourcePort == 445 {
				if strings.Contains(s, "rst=true") {
					idx++
					out.Events = append(out.Events, mkEvent(idx, "SMB", "SMB_SESSION_RESET", p, "TCP reset during SMB session establishment"))
				}
				if strings.Contains(s, "syn=true") && !strings.Contains(s, "ack=true") {
					idx++
					out.Events = append(out.Events, mkEvent(idx, "SMB", "SMB_CONNECT_TIMEOUT", p, "SMB TCP handshake failed; timeout inferred"))
				}
			}
		case "ICMP":
			if strings.Contains(s, "type=3") {
				out.Metrics.ICMP.DestinationUnreachable++
				idx++
				e := mkEvent(idx, "ICMP", "DESTINATION_UNREACHABLE", p, "ICMP destination unreachable observed")
				e.ICMPType = 3
				out.Events = append(out.Events, e)
			}
			if strings.Contains(s, "type=11") {
				out.Metrics.ICMP.TTLExceeded++
				idx++
				e := mkEvent(idx, "ICMP", "TTL_EXCEEDED", p, "ICMP TTL exceeded observed")
				e.ICMPType = 11
				out.Events = append(out.Events, e)
			}
		case "DHCP":
			key := p.SourceIP
			dhcpLastSeen[key] = p.Timestamp
			if strings.Contains(s, "msgtype=1") {
				dhcpState[key] = 1
			}
			if strings.Contains(s, "msgtype=2") && dhcpState[key] == 1 {
				dhcpState[key] = 0
			}
			if strings.Contains(s, "msgtype=3") {
				dhcpState[key] = 3
			}
			if strings.Contains(s, "msgtype=5") && dhcpState[key] == 3 {
				dhcpState[key] = 0
			}
		}
	}

	for flow, count := range dnsTimeoutCount {
		if count > 0 {
			ts := dnsTimeoutLastSeen[flow]
			if ts.IsZero() {
				ts = time.Unix(0, 0).UTC()
			}
			out.Metrics.DNS.TimeoutCount += count
			idx++
			// Derived event timestamp uses the latest packet timestamp observed for the timed-out flow.
			out.Events = append(out.Events, contracts.Event{EventID: nextID("dns", idx), Protocol: "DNS", IndicatorType: "TIMEOUT_REPEAT", Description: "Repeated DNS queries without response", Severity: "medium", TimestampUTC: ts})
		}
	}
	for src, state := range dhcpState {
		ts := dhcpLastSeen[src]
		if ts.IsZero() {
			ts = time.Unix(0, 0).UTC()
		}
		if state == 1 {
			out.Metrics.DHCP.DiscoverWithoutOffer++
			idx++
			// Derived event timestamp uses the last packet timestamp observed for this DHCP source.
			out.Events = append(out.Events, contracts.Event{EventID: nextID("dhcp", idx), Protocol: "DHCP", IndicatorType: "DISCOVER_WITHOUT_OFFER", Description: "DHCP discover without offer", SourceIP: src, TimestampUTC: ts, Severity: "medium"})
		}
		if state == 3 {
			out.Metrics.DHCP.RequestWithoutAck++
			idx++
			// Derived event timestamp uses the last packet timestamp observed for this DHCP source.
			out.Events = append(out.Events, contracts.Event{EventID: nextID("dhcp", idx), Protocol: "DHCP", IndicatorType: "REQUEST_WITHOUT_ACK", Description: "DHCP request without ACK", SourceIP: src, TimestampUTC: ts, Severity: "medium"})
		}
	}
	return out, nil
}

func mkEvent(idx int, protocol, indicator string, p contracts.ParsedPacket, desc string) contracts.Event {
	return contracts.Event{EventID: nextID(strings.ToLower(protocol), idx), TimestampUTC: p.Timestamp, Protocol: protocol, SourceIP: p.SourceIP, DestinationIP: p.DestinationIP, IndicatorType: indicator, Severity: "medium", Description: desc, SourcePort: p.SourcePort, DestinationPort: p.DestPort}
}

func nextID(prefix string, idx int) string { return fmt.Sprintf("%s_%d", prefix, idx) }

type Noop struct{}

func NewNoop() *Noop { return &Noop{} }

func (n *Noop) Detect(_ context.Context, _ Input) (Output, error) { return Output{}, nil }
