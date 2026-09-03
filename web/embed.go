package web

import "embed"

// Files contains the frontend distribution. Nift generates tracked HTML from
// web/content and web/templates; CSS, JavaScript and image assets are maintained
// directly in dist. Run `nift build` after changing tracked source.
// The explicit file list keeps Nift build metadata (dist/*.info.json) out of
// the embedded binary.
//
//go:embed dist/index.html dist/app.css dist/app-extra.css dist/script.js dist/select-chevron.svg dist/favicon.svg
var Files embed.FS
