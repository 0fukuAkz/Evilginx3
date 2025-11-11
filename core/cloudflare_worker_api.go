package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

const (
	cloudflareWorkersAPI = "https://api.cloudflare.com/client/v4"
)

// CloudflareWorkerAPI handles Cloudflare Worker deployments
type CloudflareWorkerAPI struct {
	AccountID    string
	APIToken     string
	ZoneID       string
	client       *http.Client
}

// CloudflareWorkerScript represents a deployed worker
type CloudflareWorkerScript struct {
	ID         string    `json:"id"`
	Script     string    `json:"script"`
	ETag       string    `json:"etag"`
	Size       int       `json:"size"`
	CreatedOn  time.Time `json:"created_on"`
	ModifiedOn time.Time `json:"modified_on"`
}

// CloudflareWorkerRoute represents a worker route
type CloudflareWorkerRoute struct {
	ID         string `json:"id"`
	Pattern    string `json:"pattern"`
	Script     string `json:"script"`
	ZoneID     string `json:"zone_id"`
	ZoneName   string `json:"zone_name"`
}

// CloudflareWorkerDeployment contains deployment details
type CloudflareWorkerDeployment struct {
	Name        string
	Script      string
	Bindings    []WorkerBinding
	Routes      []string
	Subdomain   bool
}

// WorkerBinding represents KV namespace or other bindings
type WorkerBinding struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	NamespaceID string `json:"namespace_id,omitempty"`
}

// CloudflareAPIResponse represents a generic API response
type CloudflareAPIResponse struct {
	Success  bool            `json:"success"`
	Errors   []APIError      `json:"errors"`
	Messages []string        `json:"messages"`
	Result   json.RawMessage `json:"result"`
}

// APIError represents an error from Cloudflare API
type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// CloudflareWorkerLog represents worker execution logs
type CloudflareWorkerLog struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Event     map[string]interface{} `json:"event"`
}

// NewCloudflareWorkerAPI creates a new Cloudflare Worker API client
func NewCloudflareWorkerAPI(accountID, apiToken, zoneID string) *CloudflareWorkerAPI {
	return &CloudflareWorkerAPI{
		AccountID: accountID,
		APIToken:  apiToken,
		ZoneID:    zoneID,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// makeRequest makes an authenticated request to Cloudflare API
func (c *CloudflareWorkerAPI) makeRequest(method, endpoint string, body interface{}) (*CloudflareAPIResponse, error) {
	url := cloudflareWorkersAPI + endpoint

	var reqBody []byte
	var err error
	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %v", err)
		}
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.APIToken)
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

	var apiResp CloudflareAPIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	if !apiResp.Success && len(apiResp.Errors) > 0 {
		return nil, fmt.Errorf("API error: %s", apiResp.Errors[0].Message)
	}

	return &apiResp, nil
}

// makeScriptRequest makes a request for worker script deployment
func (c *CloudflareWorkerAPI) makeScriptRequest(method, endpoint string, script string, metadata interface{}) (*CloudflareAPIResponse, error) {
	url := cloudflareWorkersAPI + endpoint

	// Prepare multipart form data for script upload
	body := &bytes.Buffer{}
	
	// For now, we'll use a simple approach with the script as plain text
	// In production, you'd want to use multipart/form-data for metadata
	body.WriteString(script)

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	req.Header.Set("Content-Type", "application/javascript")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var apiResp CloudflareAPIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		// If JSON parsing fails, it might be because the script was deployed successfully
		// but returns a different format
		if resp.StatusCode == 200 {
			return &CloudflareAPIResponse{Success: true}, nil
		}
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	if !apiResp.Success && len(apiResp.Errors) > 0 {
		return nil, fmt.Errorf("API error: %s", apiResp.Errors[0].Message)
	}

	return &apiResp, nil
}

// DeployWorker deploys a new worker script
func (c *CloudflareWorkerAPI) DeployWorker(deployment *CloudflareWorkerDeployment) error {
	if deployment == nil || deployment.Name == "" || deployment.Script == "" {
		return fmt.Errorf("invalid deployment configuration")
	}

	log.Info("Deploying Cloudflare Worker: %s", deployment.Name)

	// Deploy the worker script
	endpoint := fmt.Sprintf("/accounts/%s/workers/scripts/%s", c.AccountID, deployment.Name)
	
	_, err := c.makeScriptRequest("PUT", endpoint, deployment.Script, nil)
	if err != nil {
		return fmt.Errorf("failed to deploy worker: %v", err)
	}

	log.Success("Worker script '%s' deployed successfully", deployment.Name)

	// Enable subdomain if requested
	if deployment.Subdomain {
		subdomainEndpoint := fmt.Sprintf("/accounts/%s/workers/scripts/%s/subdomain", c.AccountID, deployment.Name)
		subdomainData := map[string]interface{}{
			"enabled": true,
		}
		
		if _, err := c.makeRequest("POST", subdomainEndpoint, subdomainData); err != nil {
			log.Warning("Failed to enable workers.dev subdomain: %v", err)
		} else {
			// Note: The actual subdomain is not the account ID - it's configured separately
			log.Success("Worker deployed successfully: %s", deployment.Name)
			log.Info("To get your worker URL:")
			log.Info("1. Go to Cloudflare Dashboard -> Workers & Pages")
			log.Info("2. Find your account subdomain")
			log.Info("3. Configure it with: config cloudflare_worker subdomain <your-subdomain>")
		}
	}

	// Create routes if specified
	for _, pattern := range deployment.Routes {
		if err := c.CreateWorkerRoute(deployment.Name, pattern); err != nil {
			log.Error("Failed to create route '%s': %v", pattern, err)
		}
	}

	return nil
}

// UpdateWorker updates an existing worker script
func (c *CloudflareWorkerAPI) UpdateWorker(name string, script string) error {
	if name == "" || script == "" {
		return fmt.Errorf("worker name and script are required")
	}

	log.Info("Updating Cloudflare Worker: %s", name)

	endpoint := fmt.Sprintf("/accounts/%s/workers/scripts/%s", c.AccountID, name)
	
	_, err := c.makeScriptRequest("PUT", endpoint, script, nil)
	if err != nil {
		return fmt.Errorf("failed to update worker: %v", err)
	}

	log.Success("Worker '%s' updated successfully", name)
	return nil
}

// DeleteWorker deletes a worker script
func (c *CloudflareWorkerAPI) DeleteWorker(name string) error {
	if name == "" {
		return fmt.Errorf("worker name is required")
	}

	log.Info("Deleting Cloudflare Worker: %s", name)

	endpoint := fmt.Sprintf("/accounts/%s/workers/scripts/%s", c.AccountID, name)
	
	_, err := c.makeRequest("DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to delete worker: %v", err)
	}

	log.Success("Worker '%s' deleted successfully", name)
	return nil
}

// ListWorkers returns all deployed workers
func (c *CloudflareWorkerAPI) ListWorkers() ([]CloudflareWorkerScript, error) {
	endpoint := fmt.Sprintf("/accounts/%s/workers/scripts", c.AccountID)
	
	resp, err := c.makeRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list workers: %v", err)
	}

	var workers []CloudflareWorkerScript
	if err := json.Unmarshal(resp.Result, &workers); err != nil {
		return nil, fmt.Errorf("failed to parse workers list: %v", err)
	}

	return workers, nil
}

// CreateWorkerRoute creates a route for a worker
func (c *CloudflareWorkerAPI) CreateWorkerRoute(scriptName, pattern string) error {
	if c.ZoneID == "" {
		return fmt.Errorf("zone ID is required for creating routes")
	}

	log.Info("Creating route '%s' for worker '%s'", pattern, scriptName)

	endpoint := fmt.Sprintf("/zones/%s/workers/routes", c.ZoneID)
	
	routeData := map[string]interface{}{
		"pattern": pattern,
		"script":  scriptName,
	}

	_, err := c.makeRequest("POST", endpoint, routeData)
	if err != nil {
		return fmt.Errorf("failed to create route: %v", err)
	}

	log.Success("Route '%s' created successfully", pattern)
	return nil
}

// ListWorkerRoutes lists all routes for a zone
func (c *CloudflareWorkerAPI) ListWorkerRoutes() ([]CloudflareWorkerRoute, error) {
	if c.ZoneID == "" {
		return nil, fmt.Errorf("zone ID is required")
	}

	endpoint := fmt.Sprintf("/zones/%s/workers/routes", c.ZoneID)
	
	resp, err := c.makeRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %v", err)
	}

	var routes []CloudflareWorkerRoute
	if err := json.Unmarshal(resp.Result, &routes); err != nil {
		return nil, fmt.Errorf("failed to parse routes list: %v", err)
	}

	return routes, nil
}

// DeleteWorkerRoute deletes a worker route
func (c *CloudflareWorkerAPI) DeleteWorkerRoute(routeID string) error {
	if c.ZoneID == "" || routeID == "" {
		return fmt.Errorf("zone ID and route ID are required")
	}

	endpoint := fmt.Sprintf("/zones/%s/workers/routes/%s", c.ZoneID, routeID)
	
	_, err := c.makeRequest("DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to delete route: %v", err)
	}

	log.Success("Route deleted successfully")
	return nil
}

// GetWorkerLogs retrieves logs for a worker (requires Logpush or Workers Analytics)
func (c *CloudflareWorkerAPI) GetWorkerLogs(scriptName string, hours int) ([]CloudflareWorkerLog, error) {
	// Note: This is a simplified implementation
	// Actual log retrieval requires either Workers Analytics or Logpush configuration
	log.Warning("Worker logs retrieval requires Workers Analytics subscription")
	
	// Placeholder for logs API endpoint when available
	// endpoint := fmt.Sprintf("/accounts/%s/workers/scripts/%s/tails", c.AccountID, scriptName)
	
	// This would typically return real-time logs if implemented
	return []CloudflareWorkerLog{}, nil
}

// ValidateCredentials checks if the API credentials are valid
func (c *CloudflareWorkerAPI) ValidateCredentials() error {
	endpoint := fmt.Sprintf("/accounts/%s", c.AccountID)
	
	_, err := c.makeRequest("GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("invalid credentials: %v", err)
	}

	log.Success("Cloudflare credentials validated successfully")
	return nil
}

// GetWorkerSubdomain returns the workers.dev subdomain for the account
func (c *CloudflareWorkerAPI) GetWorkerSubdomain() (string, error) {
	endpoint := fmt.Sprintf("/accounts/%s/workers/subdomain", c.AccountID)
	
	resp, err := c.makeRequest("GET", endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get subdomain: %v", err)
	}

	var result struct {
		Subdomain string `json:"subdomain"`
	}
	
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return "", fmt.Errorf("failed to parse subdomain: %v", err)
	}

	return result.Subdomain, nil
}

// GetWorkerStatus checks if a worker is deployed and active
func (c *CloudflareWorkerAPI) GetWorkerStatus(name string) (bool, error) {
	workers, err := c.ListWorkers()
	if err != nil {
		return false, err
	}

	for _, worker := range workers {
		if worker.ID == name {
			return true, nil
		}
	}

	return false, nil
}
