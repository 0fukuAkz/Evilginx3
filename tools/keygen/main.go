// keygen generates an Ed25519 key pair for the evilginx3 license system.
//
// Usage: go run tools/keygen/main.go [output_dir]
//
// Writes the private key to <output_dir>/admin.key (base64, chmod 0600).
// Overwrites core/license_pubkey.go with the new public key.
// Keep admin.key secret and off version control.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	outDir := "."
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: generate key pair: %v\n", err)
		os.Exit(1)
	}

	pubB64 := base64.StdEncoding.EncodeToString(pub)
	privB64 := base64.StdEncoding.EncodeToString(priv)

	// Write private key
	privPath := filepath.Join(outDir, "admin.key")
	if err := os.WriteFile(privPath, []byte(privB64+"\n"), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "keygen: write private key: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "private key written → %s  (keep secret, never commit)\n", privPath)

	// Overwrite core/license_pubkey.go
	pubGoSrc := "package core\n\n" +
		"// LICENSE_PUBLIC_KEY holds the base64-encoded Ed25519 public key used to verify license keys.\n" +
		"// An empty string disables license verification (development / not yet configured).\n" +
		"// Run \"make keygen\" to regenerate a key pair; that command overwrites this variable.\n" +
		"var LICENSE_PUBLIC_KEY = \"" + pubB64 + "\"\n"

	pubGoPath := filepath.Join("core", "license_pubkey.go")
	if err := os.WriteFile(pubGoPath, []byte(pubGoSrc), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "keygen: write public key source: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "public key embedded → %s\n", pubGoPath)
	fmt.Printf("public key (base64): %s\n", pubB64)
}
