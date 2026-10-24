// keygen generates an Ed25519 key pair for the evilginx3 license system.
//
// Usage: go run tools/keygen/main.go [output_dir]
//
// Writes the private key to <output_dir>/admin.key (base64, chmod 0600).
// Updates only the LICENSE_PUBLIC_KEY constant in core/license_pubkey.go,
// leaving LICENSE_DEFAULT_REVOCATION_URL and LICENSE_HEARTBEAT_URL intact.
// Keep admin.key secret and off version control.
//
// Must be run from the repository root (the directory containing core/).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

func main() {
	outDir := "."
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}

	// Verify we are in the repository root before touching any files.
	pubGoPath := filepath.Join("core", "license_pubkey.go")
	if _, err := os.Stat(pubGoPath); err != nil {
		fmt.Fprintf(os.Stderr, "keygen: must be run from the repository root (core/license_pubkey.go not found)\n")
		os.Exit(1)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: generate key pair: %v\n", err)
		os.Exit(1)
	}

	pubB64 := base64.StdEncoding.EncodeToString(pub)
	privB64 := base64.StdEncoding.EncodeToString(priv)

	// Update only the LICENSE_PUBLIC_KEY line, preserving all other constants.
	existing, err := os.ReadFile(pubGoPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: read %s: %v\n", pubGoPath, err)
		os.Exit(1)
	}
	re := regexp.MustCompile(`(const LICENSE_PUBLIC_KEY\s*=\s*)"[^"]*"`)
	updated := re.ReplaceAll(existing, []byte(`${1}"`+pubB64+`"`))
	if len(updated) == len(existing) && string(updated) == string(existing) {
		// Pattern not found — file may have a different structure; rewrite fully.
		updated = []byte("package core\n\n" +
			"// LICENSE_PUBLIC_KEY holds the base64-encoded Ed25519 public key used to verify license keys.\n" +
			"// An empty string disables license verification (development / not yet configured).\n" +
			"// Run \"make keygen\" to regenerate a key pair; that command overwrites this variable.\n" +
			"const LICENSE_PUBLIC_KEY = \"" + pubB64 + "\"\n")
	}

	if err := os.WriteFile(pubGoPath, updated, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "keygen: write public key source: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "public key embedded → %s\n", pubGoPath)

	// Create output directory if it does not exist, then write private key.
	if err := os.MkdirAll(outDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "keygen: create output directory: %v\n", err)
		os.Exit(1)
	}

	privPath := filepath.Join(outDir, "admin.key")
	if err := os.WriteFile(privPath, []byte(privB64+"\n"), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "keygen: write private key: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "private key written → %s  (keep secret, never commit)\n", privPath)

	fmt.Printf("public key (base64): %s\n", pubB64)
}
