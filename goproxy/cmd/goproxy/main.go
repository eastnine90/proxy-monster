package main

import (
	"log/slog"
	"os"

	"github.com/ridi-oss/proxy-monster/goproxy/boot"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

func main() {
	if err := run(registry); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run(registry spi.Registry) error { return boot.Run(registry) }
