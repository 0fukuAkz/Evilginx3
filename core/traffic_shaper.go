package core

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
	"golang.org/x/time/rate"
)

// TrafficShaper manages intelligent traffic shaping and rate limiting
type TrafficShaper struct {
	config           *TrafficShapingConfig
	ipLimiters       map[string]*RateLimiter
	geoLimiters      map[string]*RateLimiter
	globalLimiter    *rate.Limiter
	bandwidthManager *BandwidthManager
	adaptiveEngine   *AdaptiveEngine
	priorityQueue    *PriorityQueue
	stats            *TrafficStats
	mu               sync.RWMutex
	stopChan         chan struct{}
	isRunning        bool
}

// TrafficShapingConfig holds configuration for traffic shaping
type TrafficShapingConfig struct {
	Enabled           bool                        `json:"enabled" yaml:"enabled"`
	Mode              string                      `json:"mode" yaml:"mode"` // adaptive, strict, learning
	GlobalRateLimit   int                         `json:"global_rate_limit" yaml:"global_rate_limit"`
	GlobalBurstSize   int                         `json:"global_burst_size" yaml:"global_burst_size"`
	PerIPRateLimit    int                         `json:"per_ip_rate_limit" yaml:"per_ip_rate_limit"`
	PerIPBurstSize    int                         `json:"per_ip_burst_size" yaml:"per_ip_burst_size"`
	BandwidthLimit    int64                       `json:"bandwidth_limit" yaml:"bandwidth_limit"` // bytes per second
	AdaptiveRules     *AdaptiveRulesConfig        `json:"adaptive_rules" yaml:"adaptive_rules"`
	GeoRules          map[string]*GeoRuleConfig   `json:"geo_rules" yaml:"geo_rules"`
	PriorityRules     *PriorityRulesConfig        `json:"priority_rules" yaml:"priority_rules"`
	DDoSProtection    *DDoSProtectionConfig       `json:"ddos_protection" yaml:"ddos_protection"`
	CleanupInterval   int                         `json:"cleanup_interval" yaml:"cleanup_interval"` // minutes
}

// AdaptiveRulesConfig defines adaptive rate limiting rules
type AdaptiveRulesConfig struct {
	Enabled                bool    `json:"enabled" yaml:"enabled"`
	LearningPeriod         int     `json:"learning_period" yaml:"learning_period"` // minutes
	AnomalyThreshold       float64 `json:"anomaly_threshold" yaml:"anomaly_threshold"`
	AutoAdjust             bool    `json:"auto_adjust" yaml:"auto_adjust"`
	MinRate                int     `json:"min_rate" yaml:"min_rate"`
	MaxRate                int     `json:"max_rate" yaml:"max_rate"`
	BehaviorWeight         float64 `json:"behavior_weight" yaml:"behavior_weight"`
	TimeOfDayAdjustment    bool    `json:"time_of_day_adjustment" yaml:"time_of_day_adjustment"`
}

// GeoRuleConfig defines geographic-specific rules
type GeoRuleConfig struct {
	RateLimit      int      `json:"rate_limit" yaml:"rate_limit"`
	BurstSize      int      `json:"burst_size" yaml:"burst_size"`
	Priority       int      `json:"priority" yaml:"priority"`
	Blocked        bool     `json:"blocked" yaml:"blocked"`
	AllowedIPs     []string `json:"allowed_ips" yaml:"allowed_ips"`
	RestrictedTime string   `json:"restricted_time" yaml:"restricted_time"` // e.g., "22:00-06:00"
}

// PriorityRulesConfig defines request prioritization rules
type PriorityRulesConfig struct {
	Enabled          bool              `json:"enabled" yaml:"enabled"`
	QueueSize        int               `json:"queue_size" yaml:"queue_size"`
	ProcessingRate   int               `json:"processing_rate" yaml:"processing_rate"`
	PriorityFactors  map[string]int    `json:"priority_factors" yaml:"priority_factors"`
	DropThreshold    float64           `json:"drop_threshold" yaml:"drop_threshold"`
}

// DDoSProtectionConfig defines DDoS protection parameters
type DDoSProtectionConfig struct {
	Enabled              bool    `json:"enabled" yaml:"enabled"`
	ThresholdMultiplier  float64 `json:"threshold_multiplier" yaml:"threshold_multiplier"`
	BurstMultiplier      float64 `json:"burst_multiplier" yaml:"burst_multiplier"`
	SynFloodProtection   bool    `json:"syn_flood_protection" yaml:"syn_flood_protection"`
	SlowlorisProtection  bool    `json:"slowloris_protection" yaml:"slowloris_protection"`
	AmplificationMitigation bool `json:"amplification_mitigation" yaml:"amplification_mitigation"`
	AutoBlacklist        bool    `json:"auto_blacklist" yaml:"auto_blacklist"`
	BlacklistDuration    int     `json:"blacklist_duration" yaml:"blacklist_duration"` // minutes
}

// RateLimiter wraps a rate limiter with metadata
type RateLimiter struct {
	limiter        *rate.Limiter
	lastSeen       time.Time
	requestCount   int64
	violationCount int
	behavior       *ClientBehavior
	priority       int
	mu             sync.Mutex
}

// ClientBehavior tracks client behavior patterns
type ClientBehavior struct {
	RequestPattern   []time.Time
	ResponseTimes    []time.Duration
	ErrorRate        float64
	BandwidthUsage   int64
	SuspiciousScore  float64
	LastUpdate       time.Time
}

// BandwidthManager manages bandwidth allocation
type BandwidthManager struct {
	totalBandwidth   int64
	usedBandwidth    int64
	clientBandwidth  map[string]int64
	mu               sync.RWMutex
}

// AdaptiveEngine learns and adapts rate limits
type AdaptiveEngine struct {
	trafficPatterns  map[string]*TrafficPattern
	baselineMetrics  *BaselineMetrics
	anomalyDetector  *AnomalyDetector
	learningMode     bool
	mu               sync.RWMutex
}

// TrafficPattern represents traffic patterns for analysis
type TrafficPattern struct {
	HourlyRates    [24]float64
	DailyRates     [7]float64
	PeakTimes      []time.Time
	AverageRate    float64
	StandardDev    float64
	LastUpdated    time.Time
}

// BaselineMetrics represents normal traffic baseline
type BaselineMetrics struct {
	NormalRate      float64
	NormalBurst     float64
	NormalBandwidth int64
	GeoDistribution map[string]float64
	UpdatedAt       time.Time
}

// AnomalyDetector detects traffic anomalies
type AnomalyDetector struct {
	threshold        float64
	window           time.Duration
	recentMetrics    []float64
	anomalyCount     int
}

// PriorityQueue manages request prioritization
type PriorityQueue struct {
	items    []*QueueItem
	capacity int
	mu       sync.Mutex
}

// QueueItem represents an item in the priority queue
type QueueItem struct {
	Request   *http.Request
	Priority  int
	Timestamp time.Time
}

// TrafficStats tracks traffic statistics
type TrafficStats struct {
	TotalRequests      int64
	AllowedRequests    int64
	RateLimitedCount   int64
	DDoSBlockedCount   int64
	GeographicBlocks   map[string]int64
	BandwidthUsed      int64
	AverageLatency     time.Duration
	PeakRate           float64
	AnomalyEvents      int
	mu                 sync.RWMutex
}

// NewTrafficShaper creates a new traffic shaper
func NewTrafficShaper(config *TrafficShapingConfig) *TrafficShaper {
	ts := &TrafficShaper{
		config:         config,
		ipLimiters:     make(map[string]*RateLimiter),
		geoLimiters:    make(map[string]*RateLimiter),
		globalLimiter:  rate.NewLimiter(rate.Limit(config.GlobalRateLimit), config.GlobalBurstSize),
		stats:          &TrafficStats{
			GeographicBlocks: make(map[string]int64),
		},
		stopChan:       make(chan struct{}),
	}
	
	// Initialize bandwidth manager
	ts.bandwidthManager = &BandwidthManager{
		totalBandwidth:  config.BandwidthLimit,
		clientBandwidth: make(map[string]int64),
	}
	
	// Initialize adaptive engine
	if config.AdaptiveRules != nil && config.AdaptiveRules.Enabled {
		ts.adaptiveEngine = &AdaptiveEngine{
			trafficPatterns: make(map[string]*TrafficPattern),
			baselineMetrics: &BaselineMetrics{
				GeoDistribution: make(map[string]float64),
			},
			anomalyDetector: &AnomalyDetector{
				threshold:     config.AdaptiveRules.AnomalyThreshold,
				window:        5 * time.Minute,
				recentMetrics: make([]float64, 0),
			},
			learningMode: true,
		}
	}
	
	// Initialize priority queue
	if config.PriorityRules != nil && config.PriorityRules.Enabled {
		ts.priorityQueue = &PriorityQueue{
			items:    make([]*QueueItem, 0),
			capacity: config.PriorityRules.QueueSize,
		}
	}
	
	return ts
}

// Start begins the traffic shaping system
func (ts *TrafficShaper) Start() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	
	if ts.isRunning {
		return fmt.Errorf("traffic shaper already running")
	}
	
	ts.isRunning = true
	
	// Start cleanup worker
	go ts.cleanupWorker()
	
	// Start adaptive learning
	if ts.adaptiveEngine != nil {
		go ts.adaptiveLearningWorker()
	}
	
	// Start priority queue processor
	if ts.priorityQueue != nil {
		go ts.priorityQueueWorker()
	}
	
	// Start bandwidth monitor
	go ts.bandwidthMonitor()
	
	log.Info("Traffic shaping system started")
	return nil
}

// Stop halts the traffic shaping system
func (ts *TrafficShaper) Stop() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	
	if !ts.isRunning {
		return
	}
	
	ts.isRunning = false
	close(ts.stopChan)
	
	log.Info("Traffic shaping system stopped")
}

// ShouldAllowRequest determines if a request should be allowed
func (ts *TrafficShaper) ShouldAllowRequest(req *http.Request, clientIP string) (bool, string) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	
	if !ts.config.Enabled {
		return true, ""
	}
	
	// Update stats
	ts.stats.mu.Lock()
	ts.stats.TotalRequests++
	ts.stats.mu.Unlock()
	
	// Check global rate limit
	if !ts.globalLimiter.Allow() {
		ts.stats.mu.Lock()
		ts.stats.RateLimitedCount++
		ts.stats.mu.Unlock()
		return false, "global rate limit exceeded"
	}
	
	// Get or create IP limiter
	limiter := ts.getOrCreateIPLimiter(clientIP)
	
	// Check DDoS protection
	if ts.config.DDoSProtection != nil && ts.config.DDoSProtection.Enabled {
		if ts.isDDoSAttack(clientIP, limiter) {
			ts.stats.mu.Lock()
			ts.stats.DDoSBlockedCount++
			ts.stats.mu.Unlock()
			return false, "DDoS protection triggered"
		}
	}
	
	// Check geographic rules
	if allowed, reason := ts.checkGeographicRules(clientIP); !allowed {
		return false, reason
	}
	
	// Check adaptive rules
	if ts.adaptiveEngine != nil && !ts.adaptiveEngine.learningMode {
		if !ts.checkAdaptiveRules(clientIP, limiter) {
			return false, "adaptive rate limit exceeded"
		}
	}
	
	// Check IP rate limit
	if !limiter.limiter.Allow() {
		limiter.violationCount++
		ts.stats.mu.Lock()
		ts.stats.RateLimitedCount++
		ts.stats.mu.Unlock()
		
		// Auto-blacklist if violations exceed threshold
		if ts.config.DDoSProtection != nil && ts.config.DDoSProtection.AutoBlacklist {
			if limiter.violationCount > 10 {
				ts.blacklistIP(clientIP, ts.config.DDoSProtection.BlacklistDuration)
				return false, "IP blacklisted due to repeated violations"
			}
		}
		
		return false, "IP rate limit exceeded"
	}
	
	// Check bandwidth limit
	if !ts.checkBandwidthLimit(clientIP, req) {
		return false, "bandwidth limit exceeded"
	}
	
	// Update behavior tracking
	ts.updateClientBehavior(clientIP, limiter)
	
	// Queue request if priority rules enabled
	if ts.priorityQueue != nil {
		priority := ts.calculatePriority(req, limiter)
		ts.queueRequest(req, priority)
	}
	
	ts.stats.mu.Lock()
	ts.stats.AllowedRequests++
	ts.stats.mu.Unlock()
	
	return true, ""
}

// getOrCreateIPLimiter gets or creates a rate limiter for an IP
func (ts *TrafficShaper) getOrCreateIPLimiter(ip string) *RateLimiter {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	
	if limiter, exists := ts.ipLimiters[ip]; exists {
		limiter.lastSeen = time.Now()
		return limiter
	}
	
	// Create new limiter with adaptive rate if enabled
	rateLimit := ts.config.PerIPRateLimit
	burstSize := ts.config.PerIPBurstSize
	
	if ts.adaptiveEngine != nil {
		rateLimit, burstSize = ts.adaptiveEngine.getAdaptiveRates(ip)
	}
	
	limiter := &RateLimiter{
		limiter:  rate.NewLimiter(rate.Limit(rateLimit), burstSize),
		lastSeen: time.Now(),
		behavior: &ClientBehavior{
			RequestPattern: make([]time.Time, 0),
			ResponseTimes:  make([]time.Duration, 0),
			LastUpdate:     time.Now(),
		},
		priority: 50, // Default priority
	}
	
	ts.ipLimiters[ip] = limiter
	return limiter
}

// isDDoSAttack checks if current traffic indicates DDoS
func (ts *TrafficShaper) isDDoSAttack(ip string, limiter *RateLimiter) bool {
	// Check request rate spike
	if limiter.requestCount > int64(float64(ts.config.PerIPRateLimit)*ts.config.DDoSProtection.ThresholdMultiplier) {
		return true
	}
	
	// Check violation pattern
	if limiter.violationCount > 5 {
		return true
	}
	
	// Check anomaly detection
	if ts.adaptiveEngine != nil && ts.adaptiveEngine.anomalyDetector != nil {
		if ts.adaptiveEngine.anomalyDetector.anomalyCount > 3 {
			return true
		}
	}
	
	return false
}

// checkGeographicRules checks geographic-based rules
func (ts *TrafficShaper) checkGeographicRules(ip string) (bool, string) {
	if ts.config.GeoRules == nil {
		return true, ""
	}
	
	// Get country from IP (simplified - would use real GeoIP)
	country := ts.getCountryFromIP(ip)
	
	if rule, exists := ts.config.GeoRules[country]; exists {
		// Check if blocked
		if rule.Blocked {
			ts.stats.mu.Lock()
			ts.stats.GeographicBlocks[country]++
			ts.stats.mu.Unlock()
			return false, fmt.Sprintf("blocked by geographic rule: %s", country)
		}
		
		// Check time restrictions
		if rule.RestrictedTime != "" && ts.isInRestrictedTime(rule.RestrictedTime) {
			return false, fmt.Sprintf("access restricted for %s at this time", country)
		}
		
		// Check allowed IPs
		if len(rule.AllowedIPs) > 0 && !ts.isIPAllowed(ip, rule.AllowedIPs) {
			return false, fmt.Sprintf("IP not in allowed list for %s", country)
		}
		
		// Create geo-specific limiter if needed
		ts.mu.Lock()
		if _, exists := ts.geoLimiters[country]; !exists {
			ts.geoLimiters[country] = &RateLimiter{
				limiter:  rate.NewLimiter(rate.Limit(rule.RateLimit), rule.BurstSize),
				lastSeen: time.Now(),
			}
		}
		ts.mu.Unlock()
		
		// Check geo rate limit
		if geoLimiter := ts.geoLimiters[country]; !geoLimiter.limiter.Allow() {
			return false, fmt.Sprintf("geographic rate limit exceeded for %s", country)
		}
	}
	
	return true, ""
}

// checkAdaptiveRules checks adaptive rate limiting rules
func (ts *TrafficShaper) checkAdaptiveRules(ip string, limiter *RateLimiter) bool {
	// Get adaptive rate based on behavior
	adaptiveRate := ts.adaptiveEngine.calculateAdaptiveRate(limiter.behavior)
	
	// Update limiter if rate changed significantly
	currentRate := limiter.limiter.Limit()
	if float64(currentRate) != adaptiveRate {
		newLimiter := rate.NewLimiter(rate.Limit(adaptiveRate), int(adaptiveRate*1.5))
		limiter.limiter = newLimiter
	}
	
	return true
}

// checkBandwidthLimit checks bandwidth usage
func (ts *TrafficShaper) checkBandwidthLimit(ip string, req *http.Request) bool {
	if ts.config.BandwidthLimit == 0 {
		return true
	}
	
	// Estimate request size (simplified)
	reqSize := int64(len(req.URL.String()) + 1024) // Headers estimate
	
	ts.bandwidthManager.mu.Lock()
	defer ts.bandwidthManager.mu.Unlock()
	
	if ts.bandwidthManager.usedBandwidth+reqSize > ts.bandwidthManager.totalBandwidth {
		return false
	}
	
	ts.bandwidthManager.usedBandwidth += reqSize
	ts.bandwidthManager.clientBandwidth[ip] += reqSize
	
	return true
}

// updateClientBehavior updates client behavior tracking
func (ts *TrafficShaper) updateClientBehavior(ip string, limiter *RateLimiter) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	
	now := time.Now()
	limiter.behavior.RequestPattern = append(limiter.behavior.RequestPattern, now)
	limiter.requestCount++
	
	// Keep only recent pattern (last 100 requests)
	if len(limiter.behavior.RequestPattern) > 100 {
		limiter.behavior.RequestPattern = limiter.behavior.RequestPattern[1:]
	}
	
	// Calculate suspicious score based on patterns
	limiter.behavior.SuspiciousScore = ts.calculateSuspiciousScore(limiter.behavior)
	limiter.behavior.LastUpdate = now
}

// calculateSuspiciousScore calculates how suspicious a client is
func (ts *TrafficShaper) calculateSuspiciousScore(behavior *ClientBehavior) float64 {
	score := 0.0
	
	// Check request pattern regularity (bots often have regular patterns)
	if len(behavior.RequestPattern) > 10 {
		intervals := make([]time.Duration, 0)
		for i := 1; i < len(behavior.RequestPattern); i++ {
			intervals = append(intervals, behavior.RequestPattern[i].Sub(behavior.RequestPattern[i-1]))
		}
		
		// Calculate standard deviation
		var sum, sumSq time.Duration
		for _, interval := range intervals {
			sum += interval
			sumSq += interval * interval
		}
		avg := sum / time.Duration(len(intervals))
		variance := (sumSq / time.Duration(len(intervals))) - (avg * avg)
		
		// Low variance indicates bot-like behavior
		if variance < time.Second*time.Second {
			score += 0.3
		}
	}
	
	// High error rate
	if behavior.ErrorRate > 0.2 {
		score += 0.2
	}
	
	// Excessive bandwidth usage
	if behavior.BandwidthUsage > 10*1024*1024 { // 10MB
		score += 0.2
	}
	
	// Fast response times (might indicate automated)
	avgResponseTime := time.Duration(0)
	if len(behavior.ResponseTimes) > 0 {
		for _, rt := range behavior.ResponseTimes {
			avgResponseTime += rt
		}
		avgResponseTime /= time.Duration(len(behavior.ResponseTimes))
		
		if avgResponseTime < 100*time.Millisecond {
			score += 0.3
		}
	}
	
	return score
}

// calculatePriority calculates request priority
func (ts *TrafficShaper) calculatePriority(req *http.Request, limiter *RateLimiter) int {
	priority := limiter.priority
	
	if ts.config.PriorityRules == nil {
		return priority
	}
	
	// Adjust based on factors
	for factor, weight := range ts.config.PriorityRules.PriorityFactors {
		switch factor {
		case "authenticated":
			// Check if request has auth
			if req.Header.Get("Authorization") != "" {
				priority += weight
			}
		case "path":
			// Prioritize certain paths
			if req.URL.Path == "/api/critical" {
				priority += weight
			}
		case "method":
			// Prioritize GET over POST
			if req.Method == "GET" {
				priority += weight
			}
		case "behavior":
			// Lower priority for suspicious clients
			if limiter.behavior.SuspiciousScore > 0.5 {
				priority -= weight
			}
		}
	}
	
	return priority
}

// queueRequest adds request to priority queue
func (ts *TrafficShaper) queueRequest(req *http.Request, priority int) {
	if ts.priorityQueue == nil {
		return
	}
	
	ts.priorityQueue.mu.Lock()
	defer ts.priorityQueue.mu.Unlock()
	
	// Check if queue is full
	if len(ts.priorityQueue.items) >= ts.priorityQueue.capacity {
		// Drop lowest priority item if new item has higher priority
		lowestIdx := 0
		lowestPriority := ts.priorityQueue.items[0].Priority
		
		for i, item := range ts.priorityQueue.items {
			if item.Priority < lowestPriority {
				lowestIdx = i
				lowestPriority = item.Priority
			}
		}
		
		if priority > lowestPriority {
			// Remove lowest priority item
			ts.priorityQueue.items = append(ts.priorityQueue.items[:lowestIdx], ts.priorityQueue.items[lowestIdx+1:]...)
		} else {
			// Don't add new item
			return
		}
	}
	
	// Add new item
	ts.priorityQueue.items = append(ts.priorityQueue.items, &QueueItem{
		Request:   req,
		Priority:  priority,
		Timestamp: time.Now(),
	})
	
	// Sort by priority
	sort.Slice(ts.priorityQueue.items, func(i, j int) bool {
		return ts.priorityQueue.items[i].Priority > ts.priorityQueue.items[j].Priority
	})
}

// blacklistIP temporarily blacklists an IP
func (ts *TrafficShaper) blacklistIP(ip string, duration int) {
	// This would integrate with the main blacklist system
	log.Warning("IP %s temporarily blacklisted for %d minutes due to rate limit violations", ip, duration)
}

// getCountryFromIP gets country code from IP (simplified)
func (ts *TrafficShaper) getCountryFromIP(ip string) string {
	// In production, use real GeoIP database
	// For now, simple logic
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return "unknown"
	}
	
	// Example ranges (not real)
	if ipAddr[0] == 1 {
		return "US"
	} else if ipAddr[0] == 2 {
		return "EU"
	} else if ipAddr[0] == 3 {
		return "CN"
	}
	
	return "other"
}

// isInRestrictedTime checks if current time is in restricted period
func (ts *TrafficShaper) isInRestrictedTime(restrictedTime string) bool {
	// Parse time range like "22:00-06:00"
	// Simplified implementation
	now := time.Now()
	hour := now.Hour()
	
	// Example: restrict 22:00-06:00
	if hour >= 22 || hour < 6 {
		return true
	}
	
	return false
}

// isIPAllowed checks if IP is in allowed list
func (ts *TrafficShaper) isIPAllowed(ip string, allowedIPs []string) bool {
	for _, allowed := range allowedIPs {
		if ip == allowed {
			return true
		}
		// Could also support CIDR ranges
	}
	return false
}

// cleanupWorker periodically cleans up old limiters
func (ts *TrafficShaper) cleanupWorker() {
	ticker := time.NewTicker(time.Duration(ts.config.CleanupInterval) * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			ts.cleanup()
		case <-ts.stopChan:
			return
		}
	}
}

// cleanup removes old limiters and resets counters
func (ts *TrafficShaper) cleanup() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	
	now := time.Now()
	expiry := 30 * time.Minute
	
	// Clean up IP limiters
	for ip, limiter := range ts.ipLimiters {
		if now.Sub(limiter.lastSeen) > expiry {
			delete(ts.ipLimiters, ip)
		}
	}
	
	// Clean up geo limiters
	for geo, limiter := range ts.geoLimiters {
		if now.Sub(limiter.lastSeen) > expiry {
			delete(ts.geoLimiters, geo)
		}
	}
	
	// Reset bandwidth counters
	ts.bandwidthManager.mu.Lock()
	ts.bandwidthManager.usedBandwidth = 0
	ts.bandwidthManager.clientBandwidth = make(map[string]int64)
	ts.bandwidthManager.mu.Unlock()
	
	log.Debug("Traffic shaper cleanup completed: %d IP limiters active", len(ts.ipLimiters))
}

// adaptiveLearningWorker learns traffic patterns
func (ts *TrafficShaper) adaptiveLearningWorker() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	learningEnd := time.Now().Add(time.Duration(ts.config.AdaptiveRules.LearningPeriod) * time.Minute)
	
	for {
		select {
		case <-ticker.C:
			ts.updateTrafficPatterns()
			
			// Check if learning period is over
			if time.Now().After(learningEnd) && ts.adaptiveEngine.learningMode {
				ts.adaptiveEngine.learningMode = false
				ts.calculateBaseline()
				log.Info("Adaptive learning period completed, baseline established")
			}
			
		case <-ts.stopChan:
			return
		}
	}
}

// updateTrafficPatterns updates traffic pattern analysis
func (ts *TrafficShaper) updateTrafficPatterns() {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	
	now := time.Now()
	hour := now.Hour()
	day := int(now.Weekday())
	
	// Calculate current rate
	currentRate := float64(ts.stats.AllowedRequests) / time.Since(now.Add(-1 * time.Minute)).Minutes()
	
	// Update hourly pattern
	ts.adaptiveEngine.mu.Lock()
	if pattern, exists := ts.adaptiveEngine.trafficPatterns["global"]; exists {
		pattern.HourlyRates[hour] = (pattern.HourlyRates[hour] + currentRate) / 2
		pattern.DailyRates[day] = (pattern.DailyRates[day] + currentRate) / 2
		pattern.LastUpdated = now
	} else {
		pattern := &TrafficPattern{
			LastUpdated: now,
		}
		pattern.HourlyRates[hour] = currentRate
		pattern.DailyRates[day] = currentRate
		ts.adaptiveEngine.trafficPatterns["global"] = pattern
	}
	
	// Update anomaly detector
	ts.adaptiveEngine.anomalyDetector.recentMetrics = append(ts.adaptiveEngine.anomalyDetector.recentMetrics, currentRate)
	if len(ts.adaptiveEngine.anomalyDetector.recentMetrics) > 60 { // Keep last hour
		ts.adaptiveEngine.anomalyDetector.recentMetrics = ts.adaptiveEngine.anomalyDetector.recentMetrics[1:]
	}
	
	// Check for anomalies
	if ts.detectAnomaly(currentRate) {
		ts.adaptiveEngine.anomalyDetector.anomalyCount++
		log.Warning("Traffic anomaly detected: current rate %.2f req/min", currentRate)
	}
	ts.adaptiveEngine.mu.Unlock()
	
	// Update peak rate
	ts.stats.mu.Lock()
	if currentRate > ts.stats.PeakRate {
		ts.stats.PeakRate = currentRate
	}
	ts.stats.mu.Unlock()
}

// detectAnomaly detects if current rate is anomalous
func (ts *TrafficShaper) detectAnomaly(currentRate float64) bool {
	if len(ts.adaptiveEngine.anomalyDetector.recentMetrics) < 10 {
		return false
	}
	
	// Calculate mean and standard deviation
	var sum, sumSq float64
	for _, rate := range ts.adaptiveEngine.anomalyDetector.recentMetrics {
		sum += rate
		sumSq += rate * rate
	}
	
	mean := sum / float64(len(ts.adaptiveEngine.anomalyDetector.recentMetrics))
	variance := (sumSq / float64(len(ts.adaptiveEngine.anomalyDetector.recentMetrics))) - (mean * mean)
	stdDev := variance // sqrt would be more accurate
	
	// Check if current rate deviates significantly
	deviation := currentRate - mean
	if deviation < 0 {
		deviation = -deviation
	}
	
	return deviation > (stdDev * ts.adaptiveEngine.anomalyDetector.threshold)
}

// calculateBaseline calculates baseline metrics after learning
func (ts *TrafficShaper) calculateBaseline() {
	ts.adaptiveEngine.mu.Lock()
	defer ts.adaptiveEngine.mu.Unlock()
	
	if pattern, exists := ts.adaptiveEngine.trafficPatterns["global"]; exists {
		// Calculate average rate
		var sum float64
		var count int
		for _, rate := range pattern.HourlyRates {
			if rate > 0 {
				sum += rate
				count++
			}
		}
		
		if count > 0 {
			ts.adaptiveEngine.baselineMetrics.NormalRate = sum / float64(count)
			ts.adaptiveEngine.baselineMetrics.NormalBurst = ts.adaptiveEngine.baselineMetrics.NormalRate * 2
			ts.adaptiveEngine.baselineMetrics.UpdatedAt = time.Now()
			
			log.Info("Baseline established: normal rate %.2f req/min, burst %.2f",
				ts.adaptiveEngine.baselineMetrics.NormalRate,
				ts.adaptiveEngine.baselineMetrics.NormalBurst)
		}
	}
}

// priorityQueueWorker processes priority queue
func (ts *TrafficShaper) priorityQueueWorker() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			ts.processPriorityQueue()
		case <-ts.stopChan:
			return
		}
	}
}

// processPriorityQueue processes items in priority queue
func (ts *TrafficShaper) processPriorityQueue() {
	if ts.priorityQueue == nil {
		return
	}
	
	ts.priorityQueue.mu.Lock()
	defer ts.priorityQueue.mu.Unlock()
	
	// Process items based on rate
	processCount := ts.config.PriorityRules.ProcessingRate / 10 // Per 100ms
	
	for i := 0; i < processCount && len(ts.priorityQueue.items) > 0; i++ {
		// Remove highest priority item
		item := ts.priorityQueue.items[0]
		ts.priorityQueue.items = ts.priorityQueue.items[1:]
		
		// Process would happen here
		log.Debug("Processing queued request with priority %d", item.Priority)
	}
	
	// Drop old items if needed
	dropTime := 30 * time.Second
	now := time.Now()
	for i := len(ts.priorityQueue.items) - 1; i >= 0; i-- {
		if now.Sub(ts.priorityQueue.items[i].Timestamp) > dropTime {
			ts.priorityQueue.items = append(ts.priorityQueue.items[:i], ts.priorityQueue.items[i+1:]...)
		}
	}
}

// bandwidthMonitor monitors bandwidth usage
func (ts *TrafficShaper) bandwidthMonitor() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			ts.bandwidthManager.mu.Lock()
			used := ts.bandwidthManager.usedBandwidth
			ts.bandwidthManager.usedBandwidth = 0 // Reset per second
			ts.bandwidthManager.mu.Unlock()
			
			ts.stats.mu.Lock()
			ts.stats.BandwidthUsed += used
			ts.stats.mu.Unlock()
			
		case <-ts.stopChan:
			return
		}
	}
}

// GetStats returns traffic shaping statistics
func (ts *TrafficShaper) GetStats() map[string]interface{} {
	ts.stats.mu.RLock()
	defer ts.stats.mu.RUnlock()
	
	return map[string]interface{}{
		"enabled":            ts.config.Enabled,
		"mode":              ts.config.Mode,
		"total_requests":    ts.stats.TotalRequests,
		"allowed_requests":  ts.stats.AllowedRequests,
		"rate_limited":      ts.stats.RateLimitedCount,
		"ddos_blocked":      ts.stats.DDoSBlockedCount,
		"bandwidth_used":    ts.stats.BandwidthUsed,
		"peak_rate":         ts.stats.PeakRate,
		"anomaly_events":    ts.stats.AnomalyEvents,
		"geographic_blocks": ts.stats.GeographicBlocks,
		"active_limiters":   len(ts.ipLimiters),
		"queue_size":        0,
	}
}

// AdaptiveEngine methods

func (ae *AdaptiveEngine) getAdaptiveRates(ip string) (int, int) {
	if ae.learningMode {
		// Use default rates during learning
		return 60, 120 // Default rate and burst
	}
	
	ae.mu.RLock()
	defer ae.mu.RUnlock()
	
	// Use baseline with time-of-day adjustment
	rate := ae.baselineMetrics.NormalRate
	burst := ae.baselineMetrics.NormalBurst
	
	// Adjust for time of day
	now := time.Now()
	hour := now.Hour()
	
	if pattern, exists := ae.trafficPatterns["global"]; exists {
		if pattern.HourlyRates[hour] > 0 {
			rate = pattern.HourlyRates[hour] * 1.2 // 20% headroom
		}
	}
	
	return int(rate), int(burst)
}

func (ae *AdaptiveEngine) calculateAdaptiveRate(behavior *ClientBehavior) float64 {
	baseRate := ae.baselineMetrics.NormalRate
	
	// Adjust based on behavior
	if behavior.SuspiciousScore > 0.7 {
		return baseRate * 0.5 // Reduce rate for suspicious clients
	} else if behavior.SuspiciousScore < 0.3 {
		return baseRate * 1.5 // Increase rate for legitimate clients
	}
	
	return baseRate
}
