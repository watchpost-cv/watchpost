package web

import "embed"

// Files contains the Nift-built frontend distribution. The dist directory is
// generated from canonical Nift source under web/content and web/templates;
// edit the source, run `nift build` in this directory, and commit the result.
// The explicit file list keeps Nift build metadata (dist/*.info.json) out of
// the embedded binary.
//
//go:embed dist/index.html dist/app.css dist/app-extra.css dist/script.js dist/select-chevron.svg dist/favicon.svg
var Files embed.FS
