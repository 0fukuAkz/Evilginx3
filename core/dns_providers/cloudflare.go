package dns_providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/core"
	"github.com/kgretzky/evilginx2/log"
)

const (
	cloudflareAPIURL = "https://api.cloudflare.com/client/v4"
	defaultTTL       = 300
)

// CloudflareProvider implements the DNSProvider interface for Cloudflare
type CloudflareProvider struct {
	apiKey    string
	email     string
	apiToken  string
	client    *http.Client
	zoneCache map[string]string // domain -> zoneID cache
}

// CloudflareZone represents a Cloudflare zone
type CloudflareZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// CloudflareDNSRecord represents a Cloudflare DNS record
type CloudflareDNSRecord struct {
	ID       string `json:"id,omitempty"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Proxied  bool   `json:"proxied"`
	Priority int    `json:"priority,omitempty"`
}

// CloudflareResponse represents a Cloudflare API response
type CloudflareResponse struct {
	Success bool                   `json:"success"`
	Errors  []CloudflareError      `json:"errors"`
	Result  json.RawMessage        `json:"result"`
}

// CloudflareError represents an error from Cloudflare API
type CloudflareError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// NewCloudflareProvider creates a new Cloudflare DNS provider
func NewCloudflareProvider() *CloudflareProvider {
	return &CloudflareProvider{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		zoneCache: make(map[string]string),
	}
}

// Initialize initializes the Cloudflare provider with credentials
func (c *CloudflareProvider) Initialize(config map[string]string) error {
	// Check for API token (preferred)
	if token, ok := config["api_token"]; ok && token != "" {
		c.apiToken = token
		log.Info("Cloudflare provider initialized with API token")
		return nil
	}
	
	// Fall back to API key + email
	apiKey, hasKey := config["api_key"]
	email, hasEmail := config["email"]
	
	if !hasKey || !hasEmail || apiKey == "" || email == "" {
		return fmt.Errorf("cloudflare provider requires either 'api_token' or both 'api_key' and 'email'")
	}
	
	c.apiKey = apiKey
	c.email = email
	
	log.Info("Cloudflare provider initialized with API key")
	return nil
}

// Name returns the provider name
func (c *CloudflareProvider) Name() string {
	return "cloudflare"
}

// makeRequest makes an HTTP request to Cloudflare API
func (c *CloudflareProvider) makeRequest(method, url string, body interface{}) (*CloudflareResponse, error) {
	var reqBody []byte
	var err error
	
	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %v", err)
		}
	}
	
	req, err := http.NewRequest(method, cloudflareAPIURL+url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	
	// Set headers
	if c.apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiToken)
	} else {
		req.Header.Set("X-Auth-Email", c.email)
		req.Header.Set("X-Auth-Key", c.apiKey)
	}
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()
	
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	
	var cfResp CloudflareResponse
	if err := json.Unmarshal(respBody, &cfResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}
	
	if !cfResp.Success {
		if len(cfResp.Errors) > 0 {
			return nil, fmt.Errorf("cloudflare API error: %s", cfResp.Errors[0].Message)
		}
		return nil, fmt.Errorf("cloudflare API error: unknown error")
	}
	
	return &cfResp, nil
}

// GetZoneID returns the zone ID for a domain
func (c *CloudflareProvider) GetZoneID(domain string) (string, error) {
	// Check cache first
	if zoneID, ok := c.zoneCache[domain]; ok {
		return zoneID, nil
	}
	
	// Find the zone
	baseDomain := extractBaseDomain(domain)
	
	resp, err := c.makeRequest("GET", fmt.Sprintf("/zones?name=%s", baseDomain), nil)
	if err != nil {
		return "", err
	}
	
	var zones []CloudflareZone
	if err := json.Unmarshal(resp.Result, &zones); err != nil {
		return "", fmt.Errorf("failed to parse zones: %v", err)
	}
	
	if len(zones) == 0 {
		return "", fmt.Errorf("zone not found for domain: %s", domain)
	}
	
	zoneID := zones[0].ID
	c.zoneCache[domain] = zoneID
	
	return zoneID, nil
}

// CreateRecord creates a new DNS record
func (c *CloudflareProvider) CreateRecord(domain string, record *core.DNSRecord) error {
	zoneID, err := c.GetZoneID(domain)
	if err != nil {
		return err
	}
	
	cfRecord := CloudflareDNSRecord{
		Type:    record.Type,
		Name:    record.Name,
		Content: record.Value,
		TTL:     record.TTL,
		Proxied: false, // Don't proxy by default
	}
	
	if record.TTL == 0 {
		cfRecord.TTL = defaultTTL
	}
	
	resp, err := c.makeRequest("POST", fmt.Sprintf("/zones/%s/dns_records", zoneID), cfRecord)
	if err != nil {
		return err
	}
	
	var result CloudflareDNSRecord
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return fmt.Errorf("failed to parse created record: %v", err)
	}
	
	record.ID = result.ID
	log.Info("Created DNS record: %s %s -> %s", record.Type, record.Name, record.Value)
	
	return nil
}

// UpdateRecord updates an existing DNS record
func (c *CloudflareProvider) UpdateRecord(domain string, recordID string, record *core.DNSRecord) error {
	zoneID, err := c.GetZoneID(domain)
	if err != nil {
		return err
	}
	
	cfRecord := CloudflareDNSRecord{
		Type:    record.Type,
		Name:    record.Name,
		Content: record.Value,
		TTL:     record.TTL,
		Proxied: false,
	}
	
	if record.TTL == 0 {
		cfRecord.TTL = defaultTTL
	}
	
	_, err = c.makeRequest("PUT", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), cfRecord)
	if err != nil {
		return err
	}
	
	log.Info("Updated DNS record: %s %s -> %s", record.Type, record.Name, record.Value)
	return nil
}

// DeleteRecord deletes a DNS record
func (c *CloudflareProvider) DeleteRecord(domain string, recordID string) error {
	zoneID, err := c.GetZoneID(domain)
	if err != nil {
		return err
	}
	
	_, err = c.makeRequest("DELETE", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), nil)
	if err != nil {
		return err
	}
	
	log.Info("Deleted DNS record: %s", recordID)
	return nil
}

// GetRecords returns all DNS records for a domain
func (c *CloudflareProvider) GetRecords(domain string) ([]*core.DNSRecord, error) {
	zoneID, err := c.GetZoneID(domain)
	if err != nil {
		return nil, err
	}
	
	resp, err := c.makeRequest("GET", fmt.Sprintf("/zones/%s/dns_records", zoneID), nil)
	if err != nil {
		return nil, err
	}
	
	var cfRecords []CloudflareDNSRecord
	if err := json.Unmarshal(resp.Result, &cfRecords); err != nil {
		return nil, fmt.Errorf("failed to parse records: %v", err)
	}
	
	records := make([]*core.DNSRecord, len(cfRecords))
	for i, cfr := range cfRecords {
		records[i] = &core.DNSRecord{
			Type:  cfr.Type,
			Name:  cfr.Name,
			Value: cfr.Content,
			TTL:   cfr.TTL,
			ID:    cfr.ID,
		}
	}
	
	return records, nil
}

// GetRecord returns a specific DNS record
func (c *CloudflareProvider) GetRecord(domain string, recordID string) (*core.DNSRecord, error) {
	zoneID, err := c.GetZoneID(domain)
	if err != nil {
		return nil, err
	}
	
	resp, err := c.makeRequest("GET", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), nil)
	if err != nil {
		return nil, err
	}
	
	var cfRecord CloudflareDNSRecord
	if err := json.Unmarshal(resp.Result, &cfRecord); err != nil {
		return nil, fmt.Errorf("failed to parse record: %v", err)
	}
	
	return &core.DNSRecord{
		Type:  cfRecord.Type,
		Name:  cfRecord.Name,
		Value: cfRecord.Content,
		TTL:   cfRecord.TTL,
		ID:    cfRecord.ID,
	}, nil
}

// CreateTXTRecord creates a TXT record (for DNS challenges)
func (c *CloudflareProvider) CreateTXTRecord(domain string, name string, value string, ttl int) (string, error) {
	record := &core.DNSRecord{
		Type:  "TXT",
		Name:  name,
		Value: value,
		TTL:   ttl,
	}
	
	if ttl == 0 {
		record.TTL = 60 // Short TTL for challenges
	}
	
	err := c.CreateRecord(domain, record)
	if err != nil {
		return "", err
	}
	
	return record.ID, nil
}

// DeleteTXTRecord deletes a TXT record by ID
func (c *CloudflareProvider) DeleteTXTRecord(domain string, recordID string) error {
	return c.DeleteRecord(domain, recordID)
}

// Helper function to extract base domain from hostname
func extractBaseDomain(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		// For standard domains (example.com)
		if len(parts[len(parts)-1]) <= 3 { // TLD length check
			return strings.Join(parts[len(parts)-2:], ".")
		}
		// For longer TLDs or subdomains
		if len(parts) >= 3 {
			return strings.Join(parts[len(parts)-3:], ".")
		}
	}
	return hostname
}

// Register registers the Cloudflare provider
func Register(registry interface{}) {
	if reg, ok := registry.(*core.DNSProviderRegistry); ok {
		provider := NewCloudflareProvider()
		reg.Register("cloudflare", provider)
	}
}
