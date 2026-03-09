package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wxlfgar/wulfgar/internal/modules/capture"
	"github.com/wxlfgar/wulfgar/internal/orchestrator"
)

func main() {
	var cfg orchestrator.Config
	var listInterfaces bool

	flag.StringVar(&cfg.InterfaceName, "interface", "", "Network interface alias (required for live capture)")
	flag.DurationVar(&cfg.CaptureDuration, "duration", 5*time.Minute, "Live capture duration (example: 30s, 5m)")
	flag.Int64Var(&cfg.MaxCaptureBytes, "max-bytes", 512*1024*1024, "Maximum pcap payload bytes written")
	flag.StringVar(&cfg.OutputRoot, "out", "./output", "Output root directory")
	flag.BoolVar(&cfg.CompressBundle, "compress", false, "Compress bundle into archive")
	flag.StringVar(&cfg.InputPCAPPath, "input-pcap", "", "Offline PCAP to analyze instead of live capture")
	flag.BoolVar(&listInterfaces, "list-interfaces", false, "List available capture interfaces and exit")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "WxlfGar Phase 1 CLI\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  wulfgar.exe --interface \"Ethernet 3\" --duration 30s\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  wulfgar.exe --input-pcap .\\capture.pcap\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  wulfgar.exe --list-interfaces\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Note: this release is top-level flags only. Subcommands such as 'capture' are not currently supported.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	if listInterfaces {
		interfaces, err := capture.ListInterfaces()
		if err != nil {
			logger.Printf("module=cli severity=error err=%v", err)
			os.Exit(1)
		}
		fmt.Println("Available capture interfaces:")
		for _, iface := range interfaces {
			if iface.CaptureName == "" || iface.CaptureName == iface.Name {
				fmt.Printf("- %s\n", iface.Name)
				continue
			}
			fmt.Printf("- %s [capture device: %s]\n", iface.Name, iface.CaptureName)
		}
		return
	}

	orch := orchestrator.New(orchestrator.DefaultDependencies(logger))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := orch.Run(ctx, cfg); err != nil {
		logger.Printf("module=cli severity=error err=%v", err)
		os.Exit(1)
	}

	logger.Printf("module=cli severity=info msg=execution_complete")
}
