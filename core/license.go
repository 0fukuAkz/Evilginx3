package core

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
// Returns nil when LICENSE_PUBLIC_KEY is empty (verification disabled)
// or when the local machine is one of the admin heartbeat VPSes.
func CheckLicense(cfgDir string) error {
	if LICENSE_PUBLIC_KEY == "" || IsAdminVPS(LICENSE_HEARTBEAT_URL) {
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
		if errors.Is(err, os.ErrNotExist) {
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

	// If the license is bound to an IP, verify this machine has that IP.
	if net.ParseIP(pl.To) != nil {
		if err := checkLicenseIP(pl.To); err != nil {
			return err
		}
	}

	return nil
}

// checkLicenseIP returns nil when the host has an interface with licenseIP,
// or when the interface list cannot be read (fail-open).
func checkLicenseIP(licenseIP string) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil // fail open
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.String() == licenseIP {
				return nil
			}
		}
	}
	return fmt.Errorf("license is bound to IP %s — this machine does not have that IP", licenseIP)
}

// ValidateLicenseKey validates a license token string in-memory (no file I/O).
// Returns the parsed payload on success or an error. Skips signature check when
// LICENSE_PUBLIC_KEY is empty (verification disabled).
func ValidateLicenseKey(token string) (*licensePayload, error) {
	token = strings.TrimSpace(token)
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid license key format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid license payload encoding: %v", err)
	}

	var pl licensePayload
	if err := json.Unmarshal(payloadBytes, &pl); err != nil {
		return nil, fmt.Errorf("corrupt license data: %v", err)
	}

	if LICENSE_PUBLIC_KEY != "" {
		pubKeyBytes, err := base64.StdEncoding.DecodeString(LICENSE_PUBLIC_KEY)
		if err != nil {
			return nil, fmt.Errorf("invalid embedded public key: %v", err)
		}
		sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid license signature encoding: %v", err)
		}
		if !ed25519.Verify(pubKeyBytes, payloadBytes, sigBytes) {
			return nil, errors.New("invalid license signature")
		}
	}

	if time.Now().Unix() > pl.Exp {
		return nil, fmt.Errorf("license expired on %s", time.Unix(pl.Exp, 0).Format("2006-01-02"))
	}

	return &pl, nil
}

// IssueLicense signs a new license for issuedTo (valid for days days) using the
// Ed25519 private key at privKeyPath and writes it to <cfgDir>/license.key.
func IssueLicense(privKeyPath, cfgDir, issuedTo string, days int) error {
	if days <= 0 || days > 36500 {
		return fmt.Errorf("days must be between 1 and 36500, got %d", days)
	}

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
	for i := range privKeyBytes {
		privKeyBytes[i] = 0
	}

	token := base64.RawURLEncoding.EncodeToString(payloadBytes) + "." + base64.RawURLEncoding.EncodeToString(sig)

	licPath := filepath.Join(cfgDir, "license.key")
	tmpPath := licPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(token+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write license: %v", err)
	}
	if err := os.Rename(tmpPath, licPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to install license: %v", err)
	}

	return nil
}

// EnsureLicense checks for a valid license. If no license file exists it
// prompts the user on stdin to paste a key, validates it, saves it to
// cfgDir/license.key, then returns nil so startup can continue.
// Any other error (expired key, bad signature) is returned directly.
func EnsureLicense(cfgDir string) error {
	err := CheckLicense(cfgDir)
	if err == nil {
		return nil
	}
	if !strings.Contains(err.Error(), "no license key found") {
		return err
	}

	fmt.Println("\nNo license key found. Contact your admin to obtain one.")
	fmt.Print("Paste license key: ")
	reader := bufio.NewReader(os.Stdin)
	keyStr, _ := reader.ReadString('\n')
	keyStr = strings.TrimSpace(keyStr)
	if keyStr == "" {
		return errors.New("no license key entered")
	}

	if _, err := ValidateLicenseKey(keyStr); err != nil {
		return fmt.Errorf("invalid license key: %v", err)
	}

	licPath := filepath.Join(cfgDir, "license.key")
	tmpPath := licPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(keyStr+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to save license: %v", err)
	}
	if err := os.Rename(tmpPath, licPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to install license: %v", err)
	}

	// Run full check (including IP binding) before claiming success.
	if err := CheckLicense(cfgDir); err != nil {
		os.Remove(licPath)
		return fmt.Errorf("license rejected: %v", err)
	}

	fmt.Println("License saved. Starting...")
	return nil
}

// ReadLicenseToken returns the raw token string from cfgDir/license.key,
// or empty string if the file does not exist or cannot be read.
func ReadLicenseToken(cfgDir string) string {
	data, err := os.ReadFile(filepath.Join(cfgDir, "license.key"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// CheckRevocation fetches revoked.json from revocationURL and returns an error
// if the given token is in the revoked list. Network errors are non-fatal
// (returns nil) so an unreachable URL never blocks startup.
// Used for on-demand checks (web API). For the background ticker use CheckRevocationFast.
func CheckRevocation(token, revocationURL string) error {
	return CheckRevocationFast(token, revocationURL, nil)
}

// CheckRevocationFast is like CheckRevocation but sends a conditional GET using
// the ETag from the previous response. On 304 Not Modified it returns nil
// immediately without parsing — making 1-minute polling nearly free.
// etag is read and updated in place; pass nil to skip caching (on-demand use).
func CheckRevocationFast(token, revocationURL string, etag *string) error {
	if revocationURL == "" {
		return nil
	}

	req, err := http.NewRequest("GET", revocationURL, nil)
	if err != nil {
		return nil
	}
	if etag != nil && *etag != "" {
		req.Header.Set("If-None-Match", *etag)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil // fail open on network error
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil // revoked.json unchanged — no need to re-parse
	}
	if resp.StatusCode != http.StatusOK {
		return nil // fail open on HTTP errors
	}

	if etag != nil {
		if e := resp.Header.Get("ETag"); e != "" {
			*etag = e
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil
	}

	var payload struct {
		Revoked []string `json:"revoked"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil
	}

	h := sha256.Sum256([]byte(strings.TrimSpace(token)))
	hash := hex.EncodeToString(h[:])
	for _, r := range payload.Revoked {
		if r == hash {
			return errors.New("license has been revoked — contact the admin for a new key")
		}
	}
	return nil
}

// SendHeartbeat POSTs a heartbeat to each URL in heartbeatURL (comma-separated).
// Returns an error only when any server responds 403 (revoked).
// All network errors and non-403 HTTP responses are fail-open (nil).
func SendHeartbeat(token, heartbeatURL string) error {
	if heartbeatURL == "" || token == "" {
		return nil
	}

	h := sha256.Sum256([]byte(strings.TrimSpace(token)))
	hash := hex.EncodeToString(h[:])
	localIP := firstPublicIPv4()

	payload, _ := json.Marshal(map[string]interface{}{
		"token_hash": hash,
		"ip":         localIP,
		"ts":         time.Now().Unix(),
		"version":    VERSION,
	})

	client := &http.Client{Timeout: 10 * time.Second}
	for _, u := range strings.Split(heartbeatURL, ",") {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		resp, err := client.Post(u, "application/json", bytes.NewReader(payload))
		if err != nil {
			continue // fail open on network error
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			return errors.New("license has been revoked — contact the admin for a new key")
		}
	}
	return nil
}

// IsAdminVPS returns true when the local machine's IP matches a host in
// heartbeatURLs (comma-separated). Admin VPSes skip license enforcement.
func IsAdminVPS(heartbeatURLs string) bool {
	if heartbeatURLs == "" {
		return false
	}
	localIPs := localIPSet()
	for _, raw := range strings.Split(heartbeatURLs, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// Extract host from URL (strip scheme and port).
		host := raw
		if i := strings.Index(host, "://"); i >= 0 {
			host = host[i+3:]
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if localIPs[host] {
			return true
		}
	}
	return false
}

// localIPSet returns a set of all non-loopback IP addresses on up interfaces.
func localIPSet() map[string]bool {
	out := map[string]bool{}
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && !ip.IsLoopback() {
				out[ip.String()] = true
			}
		}
	}
	return out
}

// firstPublicIPv4 returns the first non-loopback IPv4 address on a running
// interface, or empty string when none is found.
func firstPublicIPv4() string {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && !ip.IsLoopback() && ip.To4() != nil {
				return ip.String()
			}
		}
	}
	return ""
}

// ReadLicenseInfo returns the fields of the current license.
// valid is true only when the signature is valid AND the license has not expired.
func ReadLicenseInfo(cfgDir string) (issuedTo string, issuedAt, expiresAt time.Time, valid bool, err error) {
	if LICENSE_PUBLIC_KEY == "" {
		return "n/a (verification disabled)", time.Time{}, time.Time{}, true, nil
	}

	licPath := filepath.Join(cfgDir, "license.key")
	data, e := os.ReadFile(licPath)
	if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			err = errors.New("no license key installed — place license.key in the config directory")
			return
		}
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

	pubKeyBytes, decErr := base64.StdEncoding.DecodeString(LICENSE_PUBLIC_KEY)
	sigVerified := false
	if decErr == nil && len(pubKeyBytes) == ed25519.PublicKeySize {
		if sigBytes, decErr2 := base64.RawURLEncoding.DecodeString(parts[1]); decErr2 == nil {
			sigVerified = ed25519.Verify(pubKeyBytes, payloadBytes, sigBytes)
		}
	}
	valid = sigVerified && time.Now().Unix() <= pl.Exp
	return
}
