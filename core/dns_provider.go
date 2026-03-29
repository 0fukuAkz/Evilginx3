package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

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
	log.Debug("Initializing DNS providers...")
	
	dnsConfig := m.cfg.GetDNSProviderConfig()
	if dnsConfig == nil || !dnsConfig.Enabled {
		return
	}
	
	switch strings.ToLower(dnsConfig.Provider) {
	case "cloudflare":
		provider := NewCloudflareDNSProvider()
		creds := map[string]string{
			"api_key": dnsConfig.ApiKey,
			"email":   dnsConfig.Email,
		}
		if err := provider.Initialize(creds); err != nil {
			log.Error("Failed to initialize Cloudflare DNS provider: %v", err)
			return
		}
		if err := m.registry.Register("cloudflare", provider); err != nil {
			log.Error("Failed to register Cloudflare DNS provider: %v", err)
		}
	default:
		log.Warning("Unknown DNS provider: %s", dnsConfig.Provider)
	}
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
// --- Cloudflare DNS Provider ---

const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// CloudflareDNSProvider implements DNSProvider using the Cloudflare API.
type CloudflareDNSProvider struct {
	apiKey string
	email  string
	client *http.Client
	zones  map[string]string // domain -> zoneID cache
	mu     sync.RWMutex
}

func NewCloudflareDNSProvider() *CloudflareDNSProvider {
	return &CloudflareDNSProvider{
		client: NewHTTPClient(30 * time.Second),
		zones:  make(map[string]string),
	}
}

func (p *CloudflareDNSProvider) Name() string { return "cloudflare" }

func (p *CloudflareDNSProvider) Initialize(config map[string]string) error {
	p.apiKey = config["api_key"]
	p.email = config["email"]
	if p.apiKey == "" {
		return fmt.Errorf("cloudflare: api_key is required")
	}
	log.Info("Cloudflare DNS provider initialized")
	return nil
}

func (p *CloudflareDNSProvider) setAuth(req *http.Request) {
	if p.email != "" {
		req.Header.Set("X-Auth-Email", p.email)
		req.Header.Set("X-Auth-Key", p.apiKey)
	} else {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
	req.Header.Set("Content-Type", "application/json")
}

type cfAPIResponse struct {
	Success bool            `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

type cfDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

func (p *CloudflareDNSProvider) doRequest(method, url string, body interface{}) (*cfAPIResponse, error) {
	var reqBody *bytes.Buffer
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("cloudflare: failed to marshal request: %v", err)
		}
		reqBody = bytes.NewBuffer(data)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, err
	}
	p.setAuth(req)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: failed to read response: %v", err)
	}

	var apiResp cfAPIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("cloudflare: failed to parse response: %v", err)
	}

	if !apiResp.Success {
		msg := "unknown error"
		if len(apiResp.Errors) > 0 {
			msg = apiResp.Errors[0].Message
		}
		return nil, fmt.Errorf("cloudflare API error: %s", msg)
	}

	return &apiResp, nil
}

func (p *CloudflareDNSProvider) GetZoneID(domain string) (string, error) {
	p.mu.RLock()
	if id, ok := p.zones[domain]; ok {
		p.mu.RUnlock()
		return id, nil
	}
	p.mu.RUnlock()

	url := fmt.Sprintf("%s/zones?name=%s", cloudflareAPIBase, domain)
	resp, err := p.doRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	var zones []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(resp.Result, &zones); err != nil {
		return "", fmt.Errorf("cloudflare: failed to parse zones: %v", err)
	}
	if len(zones) == 0 {
		return "", fmt.Errorf("cloudflare: zone not found for domain: %s", domain)
	}

	p.mu.Lock()
	p.zones[domain] = zones[0].ID
	p.mu.Unlock()

	return zones[0].ID, nil
}

func (p *CloudflareDNSProvider) CreateRecord(domain string, record *DNSRecord) error {
	zoneID, err := p.GetZoneID(domain)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/zones/%s/dns_records", cloudflareAPIBase, zoneID)
	payload := map[string]interface{}{
		"type":    record.Type,
		"name":    record.Name,
		"content": record.Value,
		"ttl":     record.TTL,
	}

	_, err = p.doRequest("POST", url, payload)
	return err
}

func (p *CloudflareDNSProvider) UpdateRecord(domain string, recordID string, record *DNSRecord) error {
	zoneID, err := p.GetZoneID(domain)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/zones/%s/dns_records/%s", cloudflareAPIBase, zoneID, recordID)
	payload := map[string]interface{}{
		"type":    record.Type,
		"name":    record.Name,
		"content": record.Value,
		"ttl":     record.TTL,
	}

	_, err = p.doRequest("PUT", url, payload)
	return err
}

func (p *CloudflareDNSProvider) DeleteRecord(domain string, recordID string) error {
	zoneID, err := p.GetZoneID(domain)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/zones/%s/dns_records/%s", cloudflareAPIBase, zoneID, recordID)
	_, err = p.doRequest("DELETE", url, nil)
	return err
}

func (p *CloudflareDNSProvider) GetRecords(domain string) ([]*DNSRecord, error) {
	zoneID, err := p.GetZoneID(domain)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/zones/%s/dns_records", cloudflareAPIBase, zoneID)
	resp, err := p.doRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	var cfRecords []cfDNSRecord
	if err := json.Unmarshal(resp.Result, &cfRecords); err != nil {
		return nil, fmt.Errorf("cloudflare: failed to parse records: %v", err)
	}

	records := make([]*DNSRecord, len(cfRecords))
	for i, r := range cfRecords {
		records[i] = &DNSRecord{
			ID:    r.ID,
			Type:  r.Type,
			Name:  r.Name,
			Value: r.Content,
			TTL:   r.TTL,
		}
	}
	return records, nil
}

func (p *CloudflareDNSProvider) GetRecord(domain string, recordID string) (*DNSRecord, error) {
	zoneID, err := p.GetZoneID(domain)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/zones/%s/dns_records/%s", cloudflareAPIBase, zoneID, recordID)
	resp, err := p.doRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	var r cfDNSRecord
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, fmt.Errorf("cloudflare: failed to parse record: %v", err)
	}

	return &DNSRecord{ID: r.ID, Type: r.Type, Name: r.Name, Value: r.Content, TTL: r.TTL}, nil
}

func (p *CloudflareDNSProvider) CreateTXTRecord(domain string, name string, value string, ttl int) (string, error) {
	zoneID, err := p.GetZoneID(domain)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/zones/%s/dns_records", cloudflareAPIBase, zoneID)
	payload := map[string]interface{}{
		"type":    "TXT",
		"name":    name,
		"content": value,
		"ttl":     ttl,
	}

	resp, err := p.doRequest("POST", url, payload)
	if err != nil {
		return "", err
	}

	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(resp.Result, &created); err != nil {
		return "", fmt.Errorf("cloudflare: failed to parse created record: %v", err)
	}

	return created.ID, nil
}

func (p *CloudflareDNSProvider) DeleteTXTRecord(domain string, recordID string) error {
	return p.DeleteRecord(domain, recordID)
}
