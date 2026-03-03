package contracts

import "time"

const (
	SchemaVersion = "1.0"
	ToolVersion   = "0.1"
)

type HostInfo struct {
	Hostname         string `json:"hostname"`
	OSVersion        string `json:"os_version"`
	Architecture     string `json:"architecture,omitempty"`
	PrimaryInterface string `json:"primary_interface"`
	InterfaceIP      string `json:"interface_ip"`
	InterfaceMAC     string `json:"interface_mac,omitempty"`
}

type CaptureMetadata struct {
	StartTimeUTC    time.Time `json:"start_time_utc"`
	EndTimeUTC      time.Time `json:"end_time_utc"`
	DurationSeconds int       `json:"duration_seconds"`
	Interface       string    `json:"interface"`
	PacketCount     int64     `json:"packet_count"`
	PCAPFile        string    `json:"pcap_file"`
}

type ParsedPacket struct {
	Timestamp     time.Time
	Protocol      string
	SourceIP      string
	DestinationIP string
	SourcePort    uint16
	DestPort      uint16
	Summary       string
}

type Event struct {
	EventID         string    `json:"event_id"`
	TimestampUTC    time.Time `json:"timestamp_utc"`
	Protocol        string    `json:"protocol"`
	SourceIP        string    `json:"source_ip,omitempty"`
	DestinationIP   string    `json:"destination_ip,omitempty"`
	IndicatorType   string    `json:"indicator_type"`
	Severity        string    `json:"severity,omitempty"`
	Description     string    `json:"description"`
	SliceFile       string    `json:"slice_file"`
	SourcePort      uint16    `json:"source_port,omitempty"`
	DestinationPort uint16    `json:"destination_port,omitempty"`
	RetransmitCount int       `json:"retransmit_count,omitempty"`
	ICMPType        int       `json:"icmp_type,omitempty"`
	ICMPCode        int       `json:"icmp_code,omitempty"`
}

type Metrics struct {
	DNS struct {
		NXDOMAINCount int `json:"nxdomain_count"`
		SERVFAILCount int `json:"servfail_count"`
		TimeoutCount  int `json:"timeout_count"`
	} `json:"dns"`
	TCP struct {
		SYNRetransmits  int `json:"syn_retransmits"`
		ConnectionReset int `json:"connection_resets"`
	} `json:"tcp"`
	DHCP struct {
		DiscoverWithoutOffer int `json:"discover_without_offer"`
		RequestWithoutAck    int `json:"request_without_ack"`
	} `json:"dhcp"`
	ICMP struct {
		DestinationUnreachable int `json:"destination_unreachable"`
		TTLExceeded            int `json:"ttl_exceeded"`
	} `json:"icmp"`
}

type ArtifactEntry struct {
	FileName string `json:"file_name"`
	SHA256   string `json:"sha256"`
	Type     string `json:"type"`
}

type MachineReport struct {
	SchemaVersion string          `json:"schema_version"`
	ToolVersion   string          `json:"tool_version"`
	Host          HostInfo        `json:"host"`
	Capture       CaptureMetadata `json:"capture"`
	Events        []Event         `json:"events"`
	Metrics       Metrics         `json:"metrics"`
	Artifacts     []ArtifactEntry `json:"artifacts"`
}
