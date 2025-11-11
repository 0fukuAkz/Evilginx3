package core

import (
	"fmt"
	"strings"
	"sync"

	"github.com/kgretzky/evilginx2/log"
)

// DNSRecord represents a DNS record
type DNSRecord struct {
	Type    string
	Name    string
	Value   string
	TTL     int
	ID      string
}

// DNSProvider defines the interface for DNS providers
type DNSProvider interface {
	// Initialize the provider with credentials
	Initialize(config map[string]string) error
	
	// CreateRecord creates a new DNS record
	CreateRecord(domain string, record *DNSRecord) error
	
	// UpdateRecord updates an existing DNS record
	UpdateRecord(domain string, recordID string, record *DNSRecord) error
	
	// DeleteRecord deletes a DNS record
	DeleteRecord(domain string, recordID string) error
	
	// GetRecords returns all DNS records for a domain
	GetRecords(domain string) ([]*DNSRecord, error)
	
	// GetRecord returns a specific DNS record
	GetRecord(domain string, recordID string) (*DNSRecord, error)
	
	// CreateTXTRecord creates a TXT record (for DNS challenges)
	CreateTXTRecord(domain string, name string, value string, ttl int) (string, error)
	
	// DeleteTXTRecord deletes a TXT record by ID
	DeleteTXTRecord(domain string, recordID string) error
	
	// GetZoneID returns the zone ID for a domain
	GetZoneID(domain string) (string, error)
	
	// Name returns the provider name
	Name() string
}

// DNSProviderRegistry manages DNS providers
type DNSProviderRegistry struct {
	providers map[string]DNSProvider
	mu        sync.RWMutex
}

// NewDNSProviderRegistry creates a new DNS provider registry
func NewDNSProviderRegistry() *DNSProviderRegistry {
	return &DNSProviderRegistry{
		providers: make(map[string]DNSProvider),
	}
}

// Register registers a new DNS provider
func (r *DNSProviderRegistry) Register(name string, provider DNSProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if _, exists := r.providers[name]; exists {
		return fmt.Errorf("dns provider '%s' already registered", name)
	}
	
	r.providers[name] = provider
	log.Info("Registered DNS provider: %s", name)
	return nil
}

// Get returns a DNS provider by name
func (r *DNSProviderRegistry) Get(name string) (DNSProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	provider, exists := r.providers[name]
	if !exists {
		return nil, fmt.Errorf("dns provider '%s' not found", name)
	}
	
	return provider, nil
}

// List returns all registered provider names
func (r *DNSProviderRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	
	return names
}

// DNSProviderManager manages DNS providers and domain configurations
type DNSProviderManager struct {
	cfg            *Config
	registry       *DNSProviderRegistry
	domainProvider map[string]DNSProvider // Maps domain to its provider
	mu             sync.RWMutex
}

// NewDNSProviderManager creates a new DNS provider manager
func NewDNSProviderManager(cfg *Config) *DNSProviderManager {
	manager := &DNSProviderManager{
		cfg:            cfg,
		registry:       NewDNSProviderRegistry(),
		domainProvider: make(map[string]DNSProvider),
	}
	
	// Initialize providers
	manager.initializeProviders()
	
	return manager
}

// initializeProviders initializes all configured DNS providers
func (m *DNSProviderManager) initializeProviders() {
	// This will be expanded to initialize actual providers
	// For now, it's a placeholder
	log.Debug("Initializing DNS providers...")
	
	// TODO: Initialize Cloudflare provider
	// TODO: Initialize Route53 provider  
	// TODO: Initialize Gandi provider
}

// GetProviderForDomain returns the DNS provider for a specific domain
func (m *DNSProviderManager) GetProviderForDomain(domain string) (DNSProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	// Check if domain has a specific provider
	provider, exists := m.domainProvider[domain]
	if exists {
		return provider, nil
	}
	
	// Check parent domains
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parentDomain := strings.Join(parts[i:], ".")
		provider, exists := m.domainProvider[parentDomain]
		if exists {
			return provider, nil
		}
	}
	
	// Return default provider if configured
	defaultProvider := m.cfg.GetDefaultDNSProvider()
	if defaultProvider != "" {
		return m.registry.Get(defaultProvider)
	}
	
	return nil, fmt.Errorf("no DNS provider configured for domain: %s", domain)
}

// SetProviderForDomain sets the DNS provider for a specific domain
func (m *DNSProviderManager) SetProviderForDomain(domain string, providerName string) error {
	provider, err := m.registry.Get(providerName)
	if err != nil {
		return err
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.domainProvider[domain] = provider
	log.Info("Set DNS provider '%s' for domain '%s'", providerName, domain)
	
	return nil
}

// CreateRecord creates a DNS record using the appropriate provider
func (m *DNSProviderManager) CreateRecord(domain string, record *DNSRecord) error {
	provider, err := m.GetProviderForDomain(domain)
	if err != nil {
		return err
	}
	
	return provider.CreateRecord(domain, record)
}

// UpdateRecord updates a DNS record using the appropriate provider
func (m *DNSProviderManager) UpdateRecord(domain string, recordID string, record *DNSRecord) error {
	provider, err := m.GetProviderForDomain(domain)
	if err != nil {
		return err
	}
	
	return provider.UpdateRecord(domain, recordID, record)
}

// DeleteRecord deletes a DNS record using the appropriate provider
func (m *DNSProviderManager) DeleteRecord(domain string, recordID string) error {
	provider, err := m.GetProviderForDomain(domain)
	if err != nil {
		return err
	}
	
	return provider.DeleteRecord(domain, recordID)
}

// GetRecords returns all DNS records for a domain
func (m *DNSProviderManager) GetRecords(domain string) ([]*DNSRecord, error) {
	provider, err := m.GetProviderForDomain(domain)
	if err != nil {
		return nil, err
	}
	
	return provider.GetRecords(domain)
}

// CreateDNSChallenge creates a DNS TXT record for ACME challenge
func (m *DNSProviderManager) CreateDNSChallenge(domain string, token string) (string, error) {
	provider, err := m.GetProviderForDomain(domain)
	if err != nil {
		return "", err
	}
	
	// Create _acme-challenge TXT record
	challengeName := "_acme-challenge"
	if domain != "" {
		challengeName = "_acme-challenge." + domain
	}
	
	recordID, err := provider.CreateTXTRecord(domain, challengeName, token, 60)
	if err != nil {
		return "", fmt.Errorf("failed to create DNS challenge: %v", err)
	}
	
	log.Info("Created DNS challenge record for %s", domain)
	return recordID, nil
}

// CleanupDNSChallenge removes a DNS TXT record used for ACME challenge
func (m *DNSProviderManager) CleanupDNSChallenge(domain string, recordID string) error {
	provider, err := m.GetProviderForDomain(domain)
	if err != nil {
		return err
	}
	
	err = provider.DeleteTXTRecord(domain, recordID)
	if err != nil {
		return fmt.Errorf("failed to cleanup DNS challenge: %v", err)
	}
	
	log.Info("Cleaned up DNS challenge record for %s", domain)
	return nil
}

// Helper function to extract base domain from hostname
func extractBaseDomain(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return hostname
}

// Helper function to validate DNS record type
func isValidDNSType(recordType string) bool {
	validTypes := []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV"}
	for _, valid := range validTypes {
		if recordType == valid {
			return true
		}
	}
	return false
}
