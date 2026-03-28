package core

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
	"github.com/spf13/viper"
)

// DomainStatus represents the status of a managed domain.
type DomainStatus string

const (
	DomainActive      DomainStatus = "active"
	DomainInactive    DomainStatus = "inactive"
	DomainCompromised DomainStatus = "compromised"
)

// ManagedDomain is the single domain representation used throughout the system.
type ManagedDomain struct {
	Domain       string            `json:"domain" yaml:"domain"`
	Subdomain    string            `json:"subdomain,omitempty" yaml:"subdomain,omitempty"`
	FullDomain   string            `json:"full_domain" yaml:"full_domain"`
	Status       DomainStatus      `json:"status" yaml:"status"`
	IsPrimary    bool              `json:"is_primary" yaml:"is_primary"`
	Health       int               `json:"health" yaml:"health"`
	Weight       int               `json:"weight" yaml:"weight"`
	DNSProvider  string            `json:"dns_provider,omitempty" yaml:"dns_provider,omitempty"`
	HasCert      bool              `json:"has_cert" yaml:"has_cert"`
	CreatedAt    time.Time         `json:"created_at" yaml:"created_at"`
	LastUsed     time.Time         `json:"last_used" yaml:"last_used"`
	RequestCount int64             `json:"request_count" yaml:"request_count"`
	FailureCount int               `json:"failure_count" yaml:"failure_count"`
	Description  string            `json:"description,omitempty" yaml:"description,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// DomainGenerationRules defines how to auto-generate new domains.
type DomainGenerationRules struct {
	BaseDomains     []string `json:"base_domains" yaml:"base_domains"`
	SubdomainPrefix []string `json:"subdomain_prefix" yaml:"subdomain_prefix"`
	SubdomainSuffix []string `json:"subdomain_suffix" yaml:"subdomain_suffix"`
	RandomLength    int      `json:"random_length" yaml:"random_length"`
	UseWordlist     bool     `json:"use_wordlist" yaml:"use_wordlist"`
	Wordlist        []string `json:"wordlist,omitempty" yaml:"wordlist,omitempty"`
}

// DomainHealthCheckConfig defines health check parameters.
type DomainHealthCheckConfig struct {
	Enabled       bool   `json:"enabled" yaml:"enabled"`
	Interval      int    `json:"interval" yaml:"interval"`
	Timeout       int    `json:"timeout" yaml:"timeout"`
	MaxFailures   int    `json:"max_failures" yaml:"max_failures"`
	CheckEndpoint string `json:"check_endpoint" yaml:"check_endpoint"`
}

// DomainDNSProviderConfig holds DNS provider configuration for domain rotation.
type DomainDNSProviderConfig struct {
	Provider  string            `json:"provider" yaml:"provider"`
	APIKey    string            `json:"api_key" yaml:"api_key"`
	APISecret string            `json:"api_secret" yaml:"api_secret"`
	Zone      string            `json:"zone" yaml:"zone"`
	Options   map[string]string `json:"options,omitempty" yaml:"options,omitempty"`
}

// DomainManagerConfig is the single config blob persisted under "domain_manager" in config.json.
type DomainManagerConfig struct {
	Domains          []ManagedDomain                `json:"domains" yaml:"domains"`
	RotationEnabled  bool                           `json:"rotation_enabled" yaml:"rotation_enabled"`
	Strategy         string                         `json:"strategy" yaml:"strategy"`
	RotationInterval int                            `json:"rotation_interval" yaml:"rotation_interval"`
	MaxDomains       int                            `json:"max_domains" yaml:"max_domains"`
	AutoGenerate     bool                           `json:"auto_generate" yaml:"auto_generate"`
	GenerationRules  *DomainGenerationRules         `json:"generation_rules,omitempty" yaml:"generation_rules,omitempty"`
	HealthCheck      *DomainHealthCheckConfig       `json:"health_check,omitempty" yaml:"health_check,omitempty"`
	DNSProviders     map[string]DomainDNSProviderConfig `json:"dns_providers,omitempty" yaml:"dns_providers,omitempty"`
}

// DomainHealthChecker is the interface for checking domain health.
type DomainHealthChecker interface {
	CheckDomain(domain string, endpoint string, timeout int) (int, error)
}

// HTTPDomainHealthChecker performs real HTTP health checks.
type HTTPDomainHealthChecker struct{}

func (h *HTTPDomainHealthChecker) CheckDomain(domain string, endpoint string, timeout int) (int, error) {
	if endpoint == "" {
		endpoint = "/"
	}
	if timeout <= 0 {
		timeout = 10
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	url := "https://" + domain + endpoint
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		return 100, nil
	}
	return 50, nil
}

// DomainStats tracks aggregated statistics.
type DomainStats struct {
	TotalRotations   int64            `json:"total_rotations"`
	ActiveDomains    int              `json:"active_domains"`
	CompromisedCount int64            `json:"compromised_count"`
	HealthyDomains   int              `json:"healthy_domains"`
	LastRotation     time.Time        `json:"last_rotation"`
	DomainUsage      map[string]int64 `json:"domain_usage"`
	ProviderStats    map[string]int   `json:"provider_stats"`
}

const CFG_DOMAIN_MANAGER = "domain_manager"

// DomainManager is the single, unified domain management system.
type DomainManager struct {
	mu            sync.RWMutex
	domains       map[string]*ManagedDomain
	activeDomains []string
	cfg           *viper.Viper

	// Rotation state
	rotationEnabled  bool
	strategy         string
	rotationInterval time.Duration
	maxDomains       int
	autoGenerate     bool
	generationRules  *DomainGenerationRules
	roundRobinIdx    int

	// Health checking
	healthChecker DomainHealthChecker
	healthConfig  *DomainHealthCheckConfig

	// DNS
	dnsProviders map[string]DomainDNSProviderConfig

	// Lifecycle
	isRunning bool
	stopChan  chan struct{}

	// Stats
	stats *DomainStats

	// Callback for nameserver refresh
	onDomainsChanged func([]string)
}

// NewDomainManager creates a DomainManager, loading persisted state from viper config.
func NewDomainManager(cfg *viper.Viper) *DomainManager {
	dm := &DomainManager{
		domains:       make(map[string]*ManagedDomain),
		activeDomains: make([]string, 0),
		cfg:           cfg,
		strategy:      "round-robin",
		rotationInterval: 60 * time.Minute,
		maxDomains:    10,
		dnsProviders:  make(map[string]DomainDNSProviderConfig),
		stopChan:      make(chan struct{}),
		healthChecker: &HTTPDomainHealthChecker{},
		stats: &DomainStats{
			DomainUsage:   make(map[string]int64),
			ProviderStats: make(map[string]int),
		},
	}
	dm.load()
	return dm
}

// --- Persistence ---

func (dm *DomainManager) load() {
	var dmc DomainManagerConfig
	dm.cfg.UnmarshalKey(CFG_DOMAIN_MANAGER, &dmc)

	dm.rotationEnabled = dmc.RotationEnabled
	if dmc.Strategy != "" {
		dm.strategy = dmc.Strategy
	}
	if dmc.RotationInterval > 0 {
		dm.rotationInterval = time.Duration(dmc.RotationInterval) * time.Minute
	}
	if dmc.MaxDomains > 0 {
		dm.maxDomains = dmc.MaxDomains
	}
	dm.autoGenerate = dmc.AutoGenerate
	dm.generationRules = dmc.GenerationRules
	dm.healthConfig = dmc.HealthCheck
	if dmc.DNSProviders != nil {
		dm.dnsProviders = dmc.DNSProviders
	}

	for i := range dmc.Domains {
		d := dmc.Domains[i]
		if d.Metadata == nil {
			d.Metadata = make(map[string]string)
		}
		dm.domains[d.FullDomain] = &d
	}
	dm.rebuildActiveLocked()
}

// MigrateFromLegacy converts old GeneralConfig domain fields into managed domains.
// Called once during startup from Config.NewConfig.
func (dm *DomainManager) MigrateFromLegacy(legacyDomain string, legacyDomains []LegacyDomainInfo) {
	if len(dm.domains) > 0 {
		return // already migrated
	}

	migrated := false

	// Migrate legacy single domain
	if legacyDomain != "" {
		dm.addDomainLocked(legacyDomain, "", "", "", true)
		migrated = true
	}

	// Migrate legacy multi-domain list
	for _, ld := range legacyDomains {
		if _, exists := dm.domains[ld.Domain]; exists {
			continue
		}
		md := dm.addDomainLocked(ld.Domain, "", "", ld.Description, ld.IsPrimary)
		if !ld.Enabled {
			md.Status = DomainInactive
		}
		migrated = true
	}

	if migrated {
		dm.rebuildActiveLocked()
		dm.save()
		log.Info("Migrated legacy domain configuration to unified DomainManager")
	}
}

// LegacyDomainInfo is used only for migration from old config format.
type LegacyDomainInfo struct {
	Domain    string
	IsPrimary bool
	Enabled   bool
	Description string
}

func (dm *DomainManager) save() {
	dmc := DomainManagerConfig{
		Domains:          make([]ManagedDomain, 0, len(dm.domains)),
		RotationEnabled:  dm.rotationEnabled,
		Strategy:         dm.strategy,
		RotationInterval: int(dm.rotationInterval / time.Minute),
		MaxDomains:       dm.maxDomains,
		AutoGenerate:     dm.autoGenerate,
		GenerationRules:  dm.generationRules,
		HealthCheck:      dm.healthConfig,
		DNSProviders:     dm.dnsProviders,
	}
	for _, d := range dm.domains {
		dmc.Domains = append(dmc.Domains, *d)
	}
	dm.cfg.Set(CFG_DOMAIN_MANAGER, dmc)
	dm.cfg.WriteConfig()
}

// --- Read methods (RLock) ---

func (dm *DomainManager) GetPrimaryDomain() string {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	for _, d := range dm.domains {
		if d.IsPrimary && d.Status == DomainActive {
			return d.FullDomain
		}
	}
	// Fallback to first active
	if len(dm.activeDomains) > 0 {
		return dm.activeDomains[0]
	}
	// Fallback to any domain
	for _, d := range dm.domains {
		return d.FullDomain
	}
	return ""
}

func (dm *DomainManager) GetAllDomains() []*ManagedDomain {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	result := make([]*ManagedDomain, 0, len(dm.domains))
	for _, d := range dm.domains {
		cpy := *d
		result = append(result, &cpy)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result
}

func (dm *DomainManager) GetActiveDomains() []string {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	out := make([]string, len(dm.activeDomains))
	copy(out, dm.activeDomains)
	return out
}

func (dm *DomainManager) GetDomain(fullDomain string) (*ManagedDomain, bool) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	d, ok := dm.domains[fullDomain]
	if ok {
		cpy := *d
		return &cpy, true
	}
	return nil, false
}

// IsDomainValid checks if hostname matches or is a subdomain of any active managed domain.
func (dm *DomainManager) IsDomainValid(hostname string) bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	for _, d := range dm.domains {
		if d.Status != DomainActive {
			continue
		}
		if hostname == d.FullDomain || strings.HasSuffix(hostname, "."+d.FullDomain) {
			return true
		}
	}
	return false
}

// IsRotationEnabled returns whether rotation is active.
func (dm *DomainManager) IsRotationEnabled() bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.rotationEnabled
}

// --- Write methods (full Lock) ---

// AddDomain adds a domain and sets it active immediately.
func (dm *DomainManager) AddDomain(domain, subdomain, dnsProvider, description string, primary bool) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	fullDomain := domain
	if subdomain != "" {
		fullDomain = subdomain + "." + domain
	}
	fullDomain = strings.ToLower(strings.TrimSpace(fullDomain))
	if fullDomain == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	if _, exists := dm.domains[fullDomain]; exists {
		return fmt.Errorf("domain %s already exists", fullDomain)
	}

	md := dm.addDomainLocked(domain, subdomain, dnsProvider, description, primary)
	_ = md
	dm.rebuildActiveLocked()
	dm.save()
	dm.notifyChanged()
	log.Success("Domain %s added", fullDomain)
	return nil
}

// addDomainLocked creates a ManagedDomain in the map (caller must hold Lock).
func (dm *DomainManager) addDomainLocked(domain, subdomain, dnsProvider, description string, primary bool) *ManagedDomain {
	fullDomain := domain
	if subdomain != "" {
		fullDomain = subdomain + "." + domain
	}
	fullDomain = strings.ToLower(strings.TrimSpace(fullDomain))

	if primary {
		for _, d := range dm.domains {
			d.IsPrimary = false
		}
	}

	md := &ManagedDomain{
		Domain:      strings.ToLower(strings.TrimSpace(domain)),
		Subdomain:   strings.ToLower(strings.TrimSpace(subdomain)),
		FullDomain:  fullDomain,
		Status:      DomainActive,
		IsPrimary:   primary,
		Health:      100,
		Weight:      1,
		DNSProvider: dnsProvider,
		CreatedAt:   time.Now(),
		Description: description,
		Metadata:    make(map[string]string),
	}
	dm.domains[fullDomain] = md
	return md
}

func (dm *DomainManager) RemoveDomain(fullDomain string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	fullDomain = strings.ToLower(strings.TrimSpace(fullDomain))
	_, exists := dm.domains[fullDomain]
	if !exists {
		return fmt.Errorf("domain %s not found", fullDomain)
	}

	delete(dm.domains, fullDomain)
	dm.rebuildActiveLocked()
	dm.save()
	dm.notifyChanged()
	log.Info("Domain %s removed", fullDomain)
	return nil
}

func (dm *DomainManager) SetPrimary(fullDomain string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	fullDomain = strings.ToLower(strings.TrimSpace(fullDomain))
	d, exists := dm.domains[fullDomain]
	if !exists {
		return fmt.Errorf("domain %s not found", fullDomain)
	}
	for _, dd := range dm.domains {
		dd.IsPrimary = false
	}
	d.IsPrimary = true
	dm.save()
	log.Info("Primary domain set to: %s", fullDomain)
	return nil
}

func (dm *DomainManager) SetStatus(fullDomain string, status DomainStatus) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	fullDomain = strings.ToLower(strings.TrimSpace(fullDomain))
	d, exists := dm.domains[fullDomain]
	if !exists {
		return fmt.Errorf("domain %s not found", fullDomain)
	}
	d.Status = status
	dm.rebuildActiveLocked()
	dm.save()
	dm.notifyChanged()
	return nil
}

func (dm *DomainManager) MarkCompromised(fullDomain string, reason string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	fullDomain = strings.ToLower(strings.TrimSpace(fullDomain))
	d, exists := dm.domains[fullDomain]
	if !exists {
		return fmt.Errorf("domain %s not found", fullDomain)
	}

	d.Status = DomainCompromised
	d.Health = 0
	d.Metadata["compromised_reason"] = reason
	d.Metadata["compromised_at"] = time.Now().Format(time.RFC3339)

	dm.stats.CompromisedCount++
	dm.rebuildActiveLocked()
	dm.save()
	dm.notifyChanged()

	log.Warning("Domain %s marked as compromised: %s", fullDomain, reason)

	if dm.autoGenerate {
		go dm.generateReplacement()
	}
	return nil
}

func (dm *DomainManager) SetWeight(fullDomain string, weight int) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	fullDomain = strings.ToLower(strings.TrimSpace(fullDomain))
	d, exists := dm.domains[fullDomain]
	if !exists {
		return fmt.Errorf("domain %s not found", fullDomain)
	}
	d.Weight = weight
	dm.save()
	return nil
}

// --- Rotation config setters ---

func (dm *DomainManager) SetRotationEnabled(enabled bool) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.rotationEnabled = enabled
	dm.save()
	log.Info("domain rotation enabled: %v", enabled)
}

func (dm *DomainManager) SetStrategy(strategy string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.strategy = strategy
	dm.save()
	log.Info("domain rotation strategy set to: %s", strategy)
}

func (dm *DomainManager) SetRotationInterval(minutes int) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.rotationInterval = time.Duration(minutes) * time.Minute
	dm.save()
	log.Info("domain rotation interval set to: %d minutes", minutes)
}

func (dm *DomainManager) SetMaxDomains(max int) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.maxDomains = max
	dm.save()
	log.Info("max domains set to: %d", max)
}

func (dm *DomainManager) SetAutoGenerate(enabled bool) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.autoGenerate = enabled
	dm.save()
	log.Info("domain auto-generation: %v", enabled)
}

func (dm *DomainManager) AddDNSProvider(name, provider, apiKey, apiSecret, zone string, options map[string]string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.dnsProviders[name] = DomainDNSProviderConfig{
		Provider:  provider,
		APIKey:    apiKey,
		APISecret: apiSecret,
		Zone:      zone,
		Options:   options,
	}
	dm.save()
	log.Info("DNS provider %s configured", name)
}

// SetOnDomainsChanged registers a callback invoked when the active domains list changes.
func (dm *DomainManager) SetOnDomainsChanged(fn func([]string)) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.onDomainsChanged = fn
}

// --- Rotation: GetNextDomain (full Lock) ---

func (dm *DomainManager) GetNextDomain() string {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if len(dm.activeDomains) == 0 {
		dm.rebuildActiveLocked()
		if len(dm.activeDomains) == 0 {
			return ""
		}
	}

	var next string
	switch dm.strategy {
	case "round-robin":
		next = dm.roundRobinNextLocked()
	case "weighted":
		next = dm.weightedNextLocked()
	case "health-based":
		next = dm.healthBasedNextLocked()
	case "random":
		next = dm.randomNextLocked()
	default:
		next = dm.roundRobinNextLocked()
	}

	if next != "" {
		dm.stats.DomainUsage[next]++
		if d, ok := dm.domains[next]; ok {
			d.LastUsed = time.Now()
			d.RequestCount++
		}
	}
	return next
}

func (dm *DomainManager) roundRobinNextLocked() string {
	n := len(dm.activeDomains)
	if n == 0 {
		return ""
	}
	idx := dm.roundRobinIdx % n
	dm.roundRobinIdx = (dm.roundRobinIdx + 1) % n
	return dm.activeDomains[idx]
}

func (dm *DomainManager) weightedNextLocked() string {
	if len(dm.activeDomains) == 0 {
		return ""
	}
	totalWeight := 0
	for _, domain := range dm.activeDomains {
		if d, ok := dm.domains[domain]; ok {
			totalWeight += d.Weight
		}
	}
	if totalWeight == 0 {
		return dm.randomNextLocked()
	}
	randWeight, _ := rand.Int(rand.Reader, big.NewInt(int64(totalWeight)))
	w := int(randWeight.Int64())
	for _, domain := range dm.activeDomains {
		if d, ok := dm.domains[domain]; ok {
			w -= d.Weight
			if w < 0 {
				return domain
			}
		}
	}
	return dm.activeDomains[0]
}

func (dm *DomainManager) healthBasedNextLocked() string {
	if len(dm.activeDomains) == 0 {
		return ""
	}
	healthy := make([]string, 0)
	for _, domain := range dm.activeDomains {
		if d, ok := dm.domains[domain]; ok && d.Health >= 80 {
			healthy = append(healthy, domain)
		}
	}
	if len(healthy) == 0 {
		return dm.randomNextLocked()
	}
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(healthy))))
	return healthy[idx.Int64()]
}

func (dm *DomainManager) randomNextLocked() string {
	if len(dm.activeDomains) == 0 {
		return ""
	}
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(dm.activeDomains))))
	return dm.activeDomains[idx.Int64()]
}

// --- Internal helpers ---

func (dm *DomainManager) rebuildActiveLocked() {
	active := make([]string, 0)
	healthy := 0
	for domain, d := range dm.domains {
		if d.Status == DomainActive && d.Health >= 50 {
			active = append(active, domain)
			if d.Health >= 80 {
				healthy++
			}
		}
	}
	sort.Strings(active)
	dm.activeDomains = active
	dm.stats.ActiveDomains = len(active)
	dm.stats.HealthyDomains = healthy
	dm.updateProviderStatsLocked()
}

func (dm *DomainManager) updateProviderStatsLocked() {
	stats := make(map[string]int)
	for _, d := range dm.domains {
		if d.DNSProvider != "" {
			stats[d.DNSProvider]++
		}
	}
	dm.stats.ProviderStats = stats
}

func (dm *DomainManager) notifyChanged() {
	if dm.onDomainsChanged != nil {
		out := make([]string, len(dm.activeDomains))
		copy(out, dm.activeDomains)
		go dm.onDomainsChanged(out)
	}
}

// --- Lifecycle: Start / Stop ---

func (dm *DomainManager) Start() error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if dm.isRunning {
		return fmt.Errorf("domain manager already running")
	}
	if !dm.rotationEnabled {
		return nil
	}

	dm.isRunning = true
	dm.stopChan = make(chan struct{})

	go dm.rotationWorker()

	if dm.healthConfig != nil && dm.healthConfig.Enabled {
		go dm.healthCheckWorker()
	}

	if dm.autoGenerate {
		go dm.autoGenerationWorker()
	}

	log.Info("Domain rotation system started")
	return nil
}

func (dm *DomainManager) Stop() {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if !dm.isRunning {
		return
	}
	dm.isRunning = false
	close(dm.stopChan)
	log.Info("Domain rotation system stopped")
}

// --- Background workers ---

func (dm *DomainManager) rotationWorker() {
	ticker := time.NewTicker(dm.rotationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			dm.performRotation()
		case <-dm.stopChan:
			return
		}
	}
}

func (dm *DomainManager) performRotation() {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.rebuildActiveLocked()
	dm.stats.TotalRotations++
	dm.stats.LastRotation = time.Now()
	log.Debug("Domain rotation completed: %d active domains", len(dm.activeDomains))
}

func (dm *DomainManager) healthCheckWorker() {
	interval := 5
	if dm.healthConfig != nil && dm.healthConfig.Interval > 0 {
		interval = dm.healthConfig.Interval
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			dm.performHealthChecks()
		case <-dm.stopChan:
			return
		}
	}
}

func (dm *DomainManager) performHealthChecks() {
	dm.mu.RLock()
	toCheck := make([]*ManagedDomain, 0)
	for _, d := range dm.domains {
		if d.Status == DomainActive {
			cpy := *d
			toCheck = append(toCheck, &cpy)
		}
	}
	dm.mu.RUnlock()

	endpoint := "/"
	timeout := 10
	maxFailures := 3
	if dm.healthConfig != nil {
		if dm.healthConfig.CheckEndpoint != "" {
			endpoint = dm.healthConfig.CheckEndpoint
		}
		if dm.healthConfig.Timeout > 0 {
			timeout = dm.healthConfig.Timeout
		}
		if dm.healthConfig.MaxFailures > 0 {
			maxFailures = dm.healthConfig.MaxFailures
		}
	}

	for _, checked := range toCheck {
		health, err := dm.healthChecker.CheckDomain(checked.FullDomain, endpoint, timeout)

		dm.mu.Lock()
		if d, ok := dm.domains[checked.FullDomain]; ok {
			if err != nil {
				d.FailureCount++
				log.Debug("Health check failed for %s: %v", d.FullDomain, err)
			} else {
				d.Health = health
				d.FailureCount = 0
			}
			if d.Health < 50 && d.FailureCount >= maxFailures {
				d.Status = DomainInactive
				log.Warning("Domain %s marked inactive due to health check failures", d.FullDomain)
			}
		}
		dm.mu.Unlock()
	}

	dm.mu.Lock()
	dm.rebuildActiveLocked()
	dm.mu.Unlock()
}

func (dm *DomainManager) autoGenerationWorker() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			dm.mu.RLock()
			activeCount := len(dm.activeDomains)
			maxDomains := dm.maxDomains
			dm.mu.RUnlock()
			if activeCount < maxDomains/2 {
				dm.generateReplacement()
			}
		case <-dm.stopChan:
			return
		}
	}
}

func (dm *DomainManager) generateReplacement() {
	baseDomain, subdomain, err := dm.GenerateDomain()
	if err != nil {
		log.Error("Failed to generate domain: %v", err)
		return
	}
	provider := dm.selectDNSProvider()
	err = dm.AddDomain(baseDomain, subdomain, provider, "auto-generated", false)
	if err != nil {
		log.Error("Failed to add generated domain: %v", err)
		return
	}
	log.Success("Generated new domain: %s.%s", subdomain, baseDomain)
}

// GenerateDomain produces a new (baseDomain, subdomain) pair from generation rules.
func (dm *DomainManager) GenerateDomain() (string, string, error) {
	dm.mu.RLock()
	rules := dm.generationRules
	dm.mu.RUnlock()

	if rules == nil || len(rules.BaseDomains) == 0 {
		return "", "", fmt.Errorf("no generation rules configured")
	}

	baseIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(rules.BaseDomains))))
	baseDomain := rules.BaseDomains[baseIdx.Int64()]

	var subdomain string
	if rules.UseWordlist && len(rules.Wordlist) > 0 {
		wordIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(rules.Wordlist))))
		subdomain = rules.Wordlist[wordIdx.Int64()]
	} else {
		if len(rules.SubdomainPrefix) > 0 {
			prefixIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(rules.SubdomainPrefix))))
			subdomain = rules.SubdomainPrefix[prefixIdx.Int64()]
		}
		if rules.RandomLength > 0 {
			randomBytes := make([]byte, rules.RandomLength/2+1)
			rand.Read(randomBytes)
			subdomain += hex.EncodeToString(randomBytes)[:rules.RandomLength]
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

func (dm *DomainManager) selectDNSProvider() string {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	providers := make([]string, 0, len(dm.dnsProviders))
	for name := range dm.dnsProviders {
		providers = append(providers, name)
	}
	if len(providers) == 0 {
		return ""
	}
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(providers))))
	return providers[idx.Int64()]
}

// --- Stats ---

func (dm *DomainManager) GetStats() map[string]interface{} {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return map[string]interface{}{
		"rotation_enabled":  dm.rotationEnabled,
		"strategy":          dm.strategy,
		"rotation_interval": int(dm.rotationInterval / time.Minute),
		"max_domains":       dm.maxDomains,
		"auto_generate":     dm.autoGenerate,
		"total_rotations":   dm.stats.TotalRotations,
		"active_domains":    dm.stats.ActiveDomains,
		"healthy_domains":   dm.stats.HealthyDomains,
		"compromised_count": dm.stats.CompromisedCount,
		"last_rotation":     dm.stats.LastRotation,
		"provider_stats":    dm.stats.ProviderStats,
	}
}
