package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type licensePayload struct {
	To  string `json:"to"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// CheckLicense verifies the license key in <cfgDir>/license.key.
// Returns nil when LICENSE_PUBLIC_KEY is empty (verification disabled).
func CheckLicense(cfgDir string) error {
	if LICENSE_PUBLIC_KEY == "" {
		return nil
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(LICENSE_PUBLIC_KEY)
	if err != nil {
		return fmt.Errorf("invalid embedded public key: %v", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("embedded public key has wrong size (%d bytes)", len(pubKeyBytes))
	}

	licPath := filepath.Join(cfgDir, "license.key")
	data, err := os.ReadFile(licPath)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("no license key found — obtain a license from the admin")
		}
		return fmt.Errorf("failed to read license: %v", err)
	}

	token := strings.TrimSpace(string(data))
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return errors.New("invalid license key format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("invalid license payload encoding: %v", err)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("invalid license signature encoding: %v", err)
	}

	if !ed25519.Verify(pubKeyBytes, payloadBytes, sigBytes) {
		return errors.New("invalid license signature — this key was not issued by the admin")
	}

	var pl licensePayload
	if err := json.Unmarshal(payloadBytes, &pl); err != nil {
		return fmt.Errorf("corrupt license data: %v", err)
	}

	if time.Now().Unix() > pl.Exp {
		return fmt.Errorf("license expired on %s", time.Unix(pl.Exp, 0).Format("2006-01-02"))
	}

	return nil
}

// IssueLicense signs a new license for issuedTo (valid for days days) using the
// Ed25519 private key at privKeyPath and writes it to <cfgDir>/license.key.
func IssueLicense(privKeyPath, cfgDir, issuedTo string, days int) error {
	privKeyData, err := os.ReadFile(privKeyPath)
	if err != nil {
		return fmt.Errorf("cannot read private key: %v", err)
	}

	privKeyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privKeyData)))
	if err != nil {
		return fmt.Errorf("invalid private key encoding: %v", err)
	}
	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("private key has wrong size (%d bytes, want %d)", len(privKeyBytes), ed25519.PrivateKeySize)
	}

	now := time.Now().Unix()
	exp := now + int64(days)*86400

	payload := licensePayload{To: issuedTo, Iat: now, Exp: exp}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode payload: %v", err)
	}

	sig := ed25519.Sign(ed25519.PrivateKey(privKeyBytes), payloadBytes)
	token := base64.RawURLEncoding.EncodeToString(payloadBytes) + "." + base64.RawURLEncoding.EncodeToString(sig)

	licPath := filepath.Join(cfgDir, "license.key")
	if err := os.WriteFile(licPath, []byte(token+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write license: %v", err)
	}

	return nil
}

// ReadLicenseInfo returns the fields of the current license without verifying the signature.
// valid is true when the license has not expired (and public key verification is disabled or passes).
func ReadLicenseInfo(cfgDir string) (issuedTo string, issuedAt, expiresAt time.Time, valid bool, err error) {
	if LICENSE_PUBLIC_KEY == "" {
		return "n/a (verification disabled)", time.Time{}, time.Time{}, true, nil
	}

	licPath := filepath.Join(cfgDir, "license.key")
	data, e := os.ReadFile(licPath)
	if e != nil {
		err = e
		return
	}

	token := strings.TrimSpace(string(data))
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		err = errors.New("malformed license file")
		return
	}

	payloadBytes, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		err = fmt.Errorf("malformed license payload: %v", e)
		return
	}

	var pl licensePayload
	if e := json.Unmarshal(payloadBytes, &pl); e != nil {
		err = fmt.Errorf("corrupt license data: %v", e)
		return
	}

	issuedTo = pl.To
	issuedAt = time.Unix(pl.Iat, 0)
	expiresAt = time.Unix(pl.Exp, 0)
	valid = time.Now().Unix() <= pl.Exp
	return
}
