package core

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// MLBotDetector implements machine learning based bot detection
type MLBotDetector struct {
	model          *BotDetectionModel
	featureExtractor *FeatureExtractor
	threshold      float64
	cache          map[string]*DetectionResult
	cacheMutex     sync.RWMutex
	stats          *DetectionStats
}

// BotDetectionModel represents our ML model
type BotDetectionModel struct {
	weights        map[string]float64
	bias          float64
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
	HeaderCount         int     `json:"header_count"`
	UserAgentLength     int     `json:"ua_length"`
	AcceptHeaderPresent bool    `json:"accept_present"`
	RefererPresent      bool    `json:"referer_present"`
	CookiesPresent      bool    `json:"cookies_present"`
	
	// Timing features
	RequestInterval     float64 `json:"request_interval"`
	TimeOnSite         float64 `json:"time_on_site"`
	PagesVisited       int     `json:"pages_visited"`
	RequestsPerMinute  float64 `json:"requests_per_minute"`
	
	// Behavioral features
	MouseMovements     int     `json:"mouse_movements"`
	KeystrokeCount     int     `json:"keystroke_count"`
	ScrollDepth        float64 `json:"scroll_depth"`
	FocusEvents        int     `json:"focus_events"`
	
	// Network features
	ConnectionReuse    bool    `json:"connection_reuse"`
	HTTP2Enabled       bool    `json:"http2_enabled"`
	TLSVersion         float64 `json:"tls_version"`
	CipherStrength     int     `json:"cipher_strength"`
	
	// Advanced features
	JA3Hash            string  `json:"ja3_hash"`
	HeaderOrder        string  `json:"header_order"`
	AcceptLanguageCount int    `json:"accept_lang_count"`
	EncodingTypes      int     `json:"encoding_types"`
}

// DetectionResult holds the ML prediction result
type DetectionResult struct {
	IsBot        bool    `json:"is_bot"`
	Confidence   float64 `json:"confidence"`
	Features     *RequestFeatures `json:"features"`
	Timestamp    time.Time `json:"timestamp"`
	Explanation  []string `json:"explanation"`
}

// DetectionStats tracks detection performance
type DetectionStats struct {
	TotalRequests   int64
	BotsDetected    int64
	FalsePositives  int64
	FalseNegatives  int64
	AverageLatency  time.Duration
	mu              sync.RWMutex
}

// NewMLBotDetector creates a new ML-based bot detector
func NewMLBotDetector(threshold float64) *MLBotDetector {
	detector := &MLBotDetector{
		threshold: threshold,
		cache:     make(map[string]*DetectionResult),
		stats:     &DetectionStats{},
	}
	
	// Initialize the model with pre-trained weights
	detector.model = detector.loadModel()
	detector.featureExtractor = NewFeatureExtractor()
	
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
			"header_count":          -0.15,  // Fewer headers = more bot-like
			"ua_length":             -0.08,  // Short UA = suspicious
			"accept_present":        -0.25,  // Missing Accept = bot
			"referer_present":       -0.20,  // Missing Referer = suspicious
			"cookies_present":       -0.30,  // No cookies = likely bot
			
			// Timing features weights  
			"request_interval_low":   0.40,  // Very fast requests = bot
			"request_interval_high": -0.10,  // Very slow = also suspicious
			"time_on_site":         -0.15,  // Low time = bot
			"pages_visited":        -0.05,  // Single page = suspicious
			"high_request_rate":     0.50,  // High rate = definitely bot
			
			// Behavioral features weights
			"no_mouse_movement":     0.35,  // No mouse = bot
			"no_keystrokes":         0.30,  // No typing = bot
			"no_scroll":             0.20,  // No scroll = bot
			"no_focus":              0.25,  // No focus events = bot
			
			// Network features weights
			"old_tls":               0.20,  // Old TLS = suspicious
			"weak_cipher":           0.15,  // Weak cipher = bot
			"no_http2":              0.10,  // No HTTP/2 = older client
			
			// Known bot indicators
			"bot_ja3":               0.60,  // Known bot JA3
			"suspicious_header_order": 0.30, // Unusual header order
		},
		bias: -0.5, // Slight bias towards human classification
	}
	
	// Initialize feature scaling
	model.featureScaling = &FeatureScaling{
		means: map[string]float64{
			"header_count": 15.0,
			"ua_length": 100.0,
			"request_interval": 5.0,
			"time_on_site": 30.0,
			"pages_visited": 5.0,
		},
		stds: map[string]float64{
			"header_count": 5.0,
			"ua_length": 50.0,
			"request_interval": 10.0,
			"time_on_site": 60.0,
			"pages_visited": 10.0,
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
	prepared["header_count"] = d.normalize("header_count", float64(features.HeaderCount))
	prepared["ua_length"] = d.normalize("ua_length", float64(features.UserAgentLength))
	
	// Binary features
	prepared["accept_present"] = boolToFloat(features.AcceptHeaderPresent)
	prepared["referer_present"] = boolToFloat(features.RefererPresent)
	prepared["cookies_present"] = boolToFloat(features.CookiesPresent)
	
	// Timing features with thresholds
	if features.RequestInterval < 0.5 {
		prepared["request_interval_low"] = 1.0
	}
	if features.RequestInterval > 30 {
		prepared["request_interval_high"] = 1.0
	}
	
	prepared["time_on_site"] = math.Min(features.TimeOnSite/300.0, 1.0) // Normalize to 5 min
	prepared["pages_visited"] = math.Min(float64(features.PagesVisited)/10.0, 1.0)
	
	if features.RequestsPerMinute > 30 {
		prepared["high_request_rate"] = 1.0
	}
	
	// Behavioral features
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

// GetStats returns detection statistics
func (d *MLBotDetector) GetStats() map[string]interface{} {
	d.stats.mu.RLock()
	defer d.stats.mu.RUnlock()
	
	accuracy := float64(0)
	if d.stats.TotalRequests > 0 {
		accuracy = float64(d.stats.BotsDetected) / float64(d.stats.TotalRequests) * 100
	}
	
	return map[string]interface{}{
		"total_requests":   d.stats.TotalRequests,
		"bots_detected":    d.stats.BotsDetected,
		"detection_rate":   fmt.Sprintf("%.1f%%", accuracy),
		"avg_latency_ms":   d.stats.AverageLatency.Milliseconds(),
		"cache_size":       len(d.cache),
		"model_threshold":  d.threshold,
	}
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
	ClientID      string
	WasCorrect    bool
	ActualLabel   bool // true = was bot, false = was human
	Features      *RequestFeatures
	Timestamp     time.Time
}
