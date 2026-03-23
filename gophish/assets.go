package gophish

import "embed"

//go:embed static/*
var StaticFS embed.FS

//go:embed templates/*
var TemplatesFS embed.FS

//go:embed db/*
var DBFS embed.FS
