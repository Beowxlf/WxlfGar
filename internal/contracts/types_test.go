package contracts

import "testing"

func TestArtifactsForFilesTypeInference(t *testing.T) {
	files := []string{"/tmp/a/original_capture.pcap", "/tmp/a/slices/dns_event_1.pcap", "/tmp/a/triage/nslookup.txt", "/tmp/a/summary.txt", "/tmp/a/hashes.txt"}
	hashes := map[string]string{"original_capture.pcap": "h1", "dns_event_1.pcap": "h2", "nslookup.txt": "h3", "summary.txt": "h4", "hashes.txt": "h5"}
	out := ArtifactsForFiles("/tmp/a", files, hashes)
	if len(out) != 5 {
		t.Fatalf("expected 5 artifacts, got %d", len(out))
	}
	if out[1].Type != "pcap_slice" || out[2].Type != "triage_output" {
		t.Fatalf("unexpected artifact types: %#v", out)
	}
	if out[0].FileName != "original_capture.pcap" || out[2].FileName != "triage/nslookup.txt" {
		t.Fatalf("expected relative file names, got %#v", out)
	}
}
