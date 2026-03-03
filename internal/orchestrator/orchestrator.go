package orchestrator

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/wxlfgar/wulfgar/internal/contracts"
	"github.com/wxlfgar/wulfgar/internal/modules/bundle"
	"github.com/wxlfgar/wulfgar/internal/modules/capture"
	"github.com/wxlfgar/wulfgar/internal/modules/detection"
	"github.com/wxlfgar/wulfgar/internal/modules/integrity"
	"github.com/wxlfgar/wulfgar/internal/modules/parser"
	"github.com/wxlfgar/wulfgar/internal/modules/report"
	"github.com/wxlfgar/wulfgar/internal/modules/slicer"
	"github.com/wxlfgar/wulfgar/internal/modules/triage"
)

type Logger interface {
	Printf(format string, v ...any)
}

type Config struct {
	InterfaceName   string
	CaptureDuration time.Duration
	MaxCaptureBytes int64
	OutputRoot      string
	CompressBundle  bool
	InputPCAPPath   string
}

type Dependencies struct {
	Capture   capture.Module
	Parser    parser.Module
	Detection detection.Module
	Slicer    slicer.Module
	Triage    triage.Module
	Report    report.Module
	Bundle    bundle.Module
	Integrity integrity.Module
	Logger    Logger
}

type Orchestrator struct{ deps Dependencies }

func New(deps Dependencies) *Orchestrator { return &Orchestrator{deps: deps} }

func DefaultDependencies(logger Logger) Dependencies {
	return Dependencies{
		Capture:   capture.NewDefault(),
		Parser:    parser.NewDefault(),
		Detection: detection.NewDefault(),
		Slicer:    slicer.NewDefault(),
		Triage:    triage.NewDefault(),
		Report:    report.NewDefault(),
		Bundle:    bundle.NewDefault(),
		Integrity: integrity.NewDefault(),
		Logger:    logger,
	}
}

func (o *Orchestrator) Run(ctx context.Context, cfg Config) error {
	if cfg.OutputRoot == "" {
		return fmt.Errorf("output root is required")
	}

	bundlePath, err := o.deps.Bundle.PrepareLayout(ctx, bundle.PrepareInput{OutputRoot: cfg.OutputRoot})
	if err != nil {
		return fmt.Errorf("bundle prepare: %w", err)
	}

	captureOut, err := o.deps.Capture.Run(ctx, capture.Input{
		InterfaceName: cfg.InterfaceName,
		Duration:      cfg.CaptureDuration,
		MaxBytes:      cfg.MaxCaptureBytes,
		PCAPPath:      filepath.Join(bundlePath, "original_capture.pcap"),
		InputPCAPPath: cfg.InputPCAPPath,
	})
	if err != nil {
		return fmt.Errorf("capture: %w", err)
	}
	origPath := filepath.Join(bundlePath, "original_capture.pcap")

	parsed, err := o.deps.Parser.Parse(ctx, parser.Input{PCAPPath: origPath})
	if err != nil {
		return fmt.Errorf("parser: %w", err)
	}

	detected, err := o.deps.Detection.Detect(ctx, detection.Input{Packets: parsed.Packets})
	if err != nil {
		return fmt.Errorf("detection: %w", err)
	}

	sliced, err := o.deps.Slicer.Slice(ctx, slicer.Input{PCAPPath: origPath, Events: detected.Events, SlicesPath: filepath.Join(bundlePath, "slices")})
	if err != nil {
		return fmt.Errorf("slicer: %w", err)
	}

	triageOut, err := o.deps.Triage.Run(ctx, triage.Input{Events: detected.Events, TriagePath: filepath.Join(bundlePath, "triage"), StartedAtUTC: time.Now().UTC()})
	if err != nil {
		return fmt.Errorf("triage: %w", err)
	}

	machine := contracts.MachineReport{
		SchemaVersion: contracts.SchemaVersion,
		ToolVersion:   contracts.ToolVersion,
		Host:          captureOut.Host,
		Capture:       captureOut.Metadata,
		Events:        sliced.Events,
		Metrics:       detected.Metrics,
		Artifacts:     append(sliced.Artifacts, triageOut.Artifacts...),
	}

	reportOut, err := o.deps.Report.Generate(ctx, report.Input{BundlePath: filepath.Clean(bundlePath), Machine: machine})
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}

	reportFiles := append([]string{origPath}, reportOut.Files...)
	allFiles := append(reportFiles, append(sliced.Paths, triageOut.Paths...)...)
	hashes, err := o.deps.Integrity.WriteHashes(ctx, integrity.Input{Files: allFiles, OutputPath: filepath.Join(bundlePath, "hashes.txt")})
	if err != nil {
		return fmt.Errorf("integrity: %w", err)
	}

	machine.Artifacts = contracts.ArtifactsForFiles(allFiles, hashes)
	if _, err := o.deps.Report.Generate(ctx, report.Input{BundlePath: filepath.Clean(bundlePath), Machine: machine}); err != nil {
		return fmt.Errorf("report update hashes: %w", err)
	}

	if cfg.CompressBundle {
		if _, err := o.deps.Bundle.Compress(ctx, bundlePath); err != nil {
			return fmt.Errorf("bundle compress: %w", err)
		}
	}
	if o.deps.Logger != nil {
		o.deps.Logger.Printf("module=cli severity=info msg=run_complete bundle=%s", bundlePath)
	}
	return nil
}
