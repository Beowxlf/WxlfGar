package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wxlfgar/wulfgar/internal/contracts"
)

func TestRunProducesConsistentArtifactsAndMachineHash(t *testing.T) {
	tmp := t.TempDir()
	deps := DefaultDependencies(nil)
	o := New(deps)

	err := o.Run(context.Background(), Config{
		OutputRoot:    tmp,
		InputPCAPPath: filepath.Join("..", "..", "examples", "Wulfgar_WS01_20260302_184512", "original_capture.pcap"),
	})
	if err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 bundle, got %d", len(entries))
	}
	bundlePath := filepath.Join(tmp, entries[0].Name())

	machinePath := filepath.Join(bundlePath, "machine.json")
	hashesPath := filepath.Join(bundlePath, "hashes.txt")
	machineBlob, err := os.ReadFile(machinePath)
	if err != nil {
		t.Fatal(err)
	}

	if err := validateAgainstSchema(machineBlob, filepath.Join("..", "..", "schemas", "machine.schema.json")); err != nil {
		t.Fatalf("schema validation failed: %v", err)
	}
	var machine contracts.MachineReport
	if err := json.Unmarshal(machineBlob, &machine); err != nil {
		t.Fatal(err)
	}
	if machine.SchemaVersion != contracts.SchemaVersion {
		t.Fatalf("schema version mismatch: %s", machine.SchemaVersion)
	}
	if machine.Host.Hostname == "" || machine.Capture.PCAPFile == "" {
		t.Fatal("required machine fields are empty")
	}
	if len(machine.Artifacts) == 0 {
		t.Fatal("artifacts missing")
	}

	artifactNames := map[string]struct{}{}
	for _, a := range machine.Artifacts {
		artifactNames[filepath.Base(a.FileName)] = struct{}{}
	}
	for _, required := range []string{"machine.json", "summary.txt", "hashes.txt", "original_capture.pcap"} {
		if _, ok := artifactNames[required]; !ok {
			t.Fatalf("missing required artifact %s", required)
		}
	}

	hashesBlob, err := os.ReadFile(hashesPath)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(machineBlob)
	line := "SHA256(machine.json)=" + hex.EncodeToString(h[:])
	if !strings.Contains(string(hashesBlob), line) {
		t.Fatalf("hashes.txt missing current machine hash; expected line %q", line)
	}
}

func TestOfflineRunDoesNotClaimLiveInterfaceInMetadata(t *testing.T) {
	tmp := t.TempDir()
	o := New(DefaultDependencies(nil))

	err := o.Run(context.Background(), Config{
		OutputRoot:    tmp,
		InterfaceName: "Ethernet 3",
		InputPCAPPath: filepath.Join("..", "..", "examples", "Wulfgar_WS01_20260302_184512", "original_capture.pcap"),
	})
	if err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 bundle, got %d", len(entries))
	}

	machinePath := filepath.Join(tmp, entries[0].Name(), "machine.json")
	blob, err := os.ReadFile(machinePath)
	if err != nil {
		t.Fatal(err)
	}
	var machine contracts.MachineReport
	if err := json.Unmarshal(blob, &machine); err != nil {
		t.Fatal(err)
	}
	if machine.Host.PrimaryInterface != "" {
		t.Fatalf("offline run should not claim host primary interface; got %q", machine.Host.PrimaryInterface)
	}
	if machine.Capture.Interface != "" {
		t.Fatalf("offline run should not claim capture interface; got %q", machine.Capture.Interface)
	}
}

func validateAgainstSchema(machineJSON []byte, schemaPath string) error {
	var schema map[string]any
	var machine map[string]any
	if err := json.Unmarshal(machineJSON, &machine); err != nil {
		return err
	}
	blob, err := os.ReadFile(schemaPath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(blob, &schema); err != nil {
		return err
	}
	required, _ := schema["required"].([]any)
	for _, r := range required {
		k := fmt.Sprint(r)
		if _, ok := machine[k]; !ok {
			return fmt.Errorf("missing top-level required key %s", k)
		}
	}
	props, _ := schema["properties"].(map[string]any)
	if sv, ok := props["schema_version"].(map[string]any); ok {
		if c, ok := sv["const"].(string); ok && machine["schema_version"] != c {
			return fmt.Errorf("schema_version const mismatch: got %v want %s", machine["schema_version"], c)
		}
	}
	if captureSchema, ok := props["capture"].(map[string]any); ok {
		capObj, _ := machine["capture"].(map[string]any)
		req, _ := captureSchema["required"].([]any)
		for _, r := range req {
			k := fmt.Sprint(r)
			if _, ok := capObj[k]; !ok {
				return fmt.Errorf("missing capture required key %s", k)
			}
		}
	}
	return nil
}
