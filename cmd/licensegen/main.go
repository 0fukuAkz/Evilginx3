// licensegen generates a signed license key for evilginx3.
// The -to value should be the user's VPS public IP address; evilginx verifies
// at startup that the machine's network interfaces include that IP.
//
// Usage:
//
//	go run cmd/licensegen/main.go -admin-key ./admin.key -to 1.2.3.4 -days 365
//	./build/licensegen -admin-key ./admin.key -to 1.2.3.4 -days 365
//
// Prints the license token to stdout. Pipe or copy it to the recipient.
// Keep admin.key secret and never distribute it.
// For full license management (list, revoke, renew, heartbeat server) use the
// standalone evilginx-licensegen tool: gitlab.com/0fukuAkz/evilginx-licensegen
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	adminKeyPath := flag.String("admin-key", "admin.key", "Path to the Ed25519 private key file")
	issuedTo := flag.String("to", "", "Who this license is issued to (required)")
	days := flag.Int("days", 365, "License validity in days (1–36500)")
	flag.Parse()

	if *issuedTo == "" {
		fmt.Fprintln(os.Stderr, "licensegen: -to is required")
		flag.Usage()
		os.Exit(1)
	}
	if *days < 1 || *days > 36500 {
		fmt.Fprintln(os.Stderr, "licensegen: -days must be between 1 and 36500")
		os.Exit(1)
	}

	privKeyData, err := os.ReadFile(*adminKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "licensegen: cannot read %s: %v\n", *adminKeyPath, err)
		os.Exit(1)
	}

	privKeyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privKeyData)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "licensegen: invalid private key encoding: %v\n", err)
		os.Exit(1)
	}
	if len(privKeyBytes) != ed25519.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "licensegen: private key has wrong size (%d bytes, want %d)\n", len(privKeyBytes), ed25519.PrivateKeySize)
		os.Exit(1)
	}

	now := time.Now().Unix()
	payload := struct {
		To  string `json:"to"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}{
		To:  *issuedTo,
		Iat: now,
		Exp: now + int64(*days)*86400,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "licensegen: failed to encode payload: %v\n", err)
		os.Exit(1)
	}

	sig := ed25519.Sign(ed25519.PrivateKey(privKeyBytes), payloadBytes)
	for i := range privKeyBytes {
		privKeyBytes[i] = 0
	}

	token := base64.RawURLEncoding.EncodeToString(payloadBytes) + "." + base64.RawURLEncoding.EncodeToString(sig)

	fmt.Fprintf(os.Stderr, "issued to: %s  |  expires: %s  (%d days)\n",
		*issuedTo,
		time.Unix(payload.Exp, 0).Format("2006-01-02"),
		*days,
	)
	fmt.Println(token)
}
