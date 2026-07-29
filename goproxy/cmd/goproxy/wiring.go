package main

import (
	"github.com/ridi-oss/proxy-monster/goproxy/dialects"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

var registry spi.Registry = dialects.Registry()
