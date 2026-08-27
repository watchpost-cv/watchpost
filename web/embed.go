package web

import "embed"

// Files contains the Nift-built frontend distribution.
//
//go:embed dist/*
var Files embed.FS
