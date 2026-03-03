package contracts

import "testing"

func TestArtifactsForFilesTypeInference(t *testing.T) {
	files := []string{"/tmp/a/original_capture.pcap", "/tmp/a/slices/dns_event_1.pcap", "/tmp/a/triage/nslookup.txt", "/tmp/a/summary.txt"}
	hashes := map[string]string{"original_capture.pcap": "h1", "dns_event_1.pcap": "h2", "nslookup.txt": "h3", "summary.txt": "h4"}
	out := ArtifactsForFiles(files, hashes)
	if len(out) != 4 {
		t.Fatalf("expected 4 artifacts, got %d", len(out))
	}
	if out[1].Type != "pcap_slice" || out[2].Type != "triage_output" {
		t.Fatalf("unexpected artifact types: %#v", out)
	}
}
