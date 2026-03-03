package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wxlfgar/wulfgar/internal/orchestrator"
)

func main() {
	var cfg orchestrator.Config
	flag.StringVar(&cfg.InterfaceName, "interface", "", "Network interface name to capture")
	flag.DurationVar(&cfg.CaptureDuration, "duration", 5*time.Minute, "Capture duration")
	flag.Int64Var(&cfg.MaxCaptureBytes, "max-bytes", 512*1024*1024, "Maximum pcap size in bytes")
	flag.StringVar(&cfg.OutputRoot, "out", "./output", "Output root directory")
	flag.BoolVar(&cfg.CompressBundle, "compress", false, "Compress bundle into archive")
	flag.StringVar(&cfg.InputPCAPPath, "input-pcap", "", "Optional offline PCAP to analyze instead of live capture")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	orch := orchestrator.New(orchestrator.DefaultDependencies(logger))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := orch.Run(ctx, cfg); err != nil {
		logger.Printf("module=cli severity=error err=%v", err)
		os.Exit(1)
	}

	logger.Printf("module=cli severity=info msg=execution_complete")
}
