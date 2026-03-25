package gophish

import "embed"

//go:embed all:static
var StaticFS embed.FS

//go:embed all:templates
var TemplatesFS embed.FS

//go:embed all:db
var DBFS embed.FS
