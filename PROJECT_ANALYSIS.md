# Evilginx 3.3.1 Private Dev Edition - Project Analysis

## Executive Summary

**Project Type:** Phishing Framework / Man-in-the-Middle Attack Tool  
**Version:** 3.3.1 - Private Dev Edition  
**Language:** Go 1.22  
**Original Author:** Kuba Gretzky (@mrgretzky)  
**Modified By:** AKaZA (Akz0fuku)  
**License:** BSD-3 Clause  
**Primary Purpose:** Authorized penetration testing and red team engagements  
**Codebase Size:** 41 Go source files, ~21,098 lines of code (core module), 2.7MB total

---

## 1. Project Overview

### 1.1 Purpose and Functionality

Evilginx is a sophisticated **man-in-the-middle (MITM) attack framework** designed to:

- **Intercept and capture login credentials** from legitimate websites
- **Bypass 2-factor authentication (2FA)** by stealing session cookies
- **Proxy requests** between victims and legitimate services in real-time
- **Evade detection** through advanced anti-bot and anti-sandbox techniques
- **Automate phishing campaigns** with customizable lures and phishlets

This is a **private development edition** that extends the standard Evilginx 3.3 with enterprise-grade features specifically designed for advanced red team operations.

### 1.2 Key Capabilities

✅ **Real-time MITM proxying** - Intercepts HTTPS traffic transparently  
✅ **Session cookie capture** - Bypasses 2FA by stealing authenticated sessions  
✅ **TLS certificate management** - Automatic LetsEncrypt certificates  
✅ **Phishlet system** - Template-based phishing page configuration  
✅ **Multi-platform support** - Linux and Windows deployment  
✅ **Advanced evasion** - ML bot detection, JA3 fingerprinting, sandbox detection

---

## 2. Architecture Analysis

### 2.1 Core Components

The project is structured into several key modules:

#### **Core Module** (`/core/` - 35 files)

The heart of the application containing:

| Component | File | Purpose |
|-----------|------|---------|
| **HTTP Proxy** | `http_proxy.go` | Main MITM proxy server (2,779 lines) |
| **ML Bot Detection** | `ml_detector.go` | Machine learning-based bot detection (487 lines) |
| **JA3 Fingerprinting** | `ja3_fingerprint.go` | TLS fingerprint analysis (477 lines) |
| **Sandbox Detection** | `sandbox_detector.go` | VM and analysis tool detection |
| **Polymorphic Engine** | `polymorphic_engine.go` | Dynamic JavaScript code mutation |
| **Traffic Shaper** | `traffic_shaper.go` | Rate limiting and DDoS protection |
| **Domain Rotation** | `domain_rotation.go` | Automated domain switching |
| **C2 Channel** | `c2_channel.go` | Command and control infrastructure |
| **TLS Interceptor** | `tls_interceptor.go` | Advanced certificate management |
| **Telegram Bot** | `telegram.go`, `telegram_exporter.go` | Real-time notifications |
| **Cloudflare Worker** | `cloudflare_worker.go`, `cloudflare_worker_api.go` | Proxy bypass capabilities |
| **Phishlet Manager** | `phishlet.go` | Phishing template management |
| **Session Manager** | `session.go` | Victim session tracking |
| **Config Manager** | `config.go` | Configuration management (1,473 lines) |
| **Certificate DB** | `certdb.go` | TLS certificate database |
| **DNS Server** | `nameserver.go` | Custom DNS server |
| **Terminal Interface** | `terminal.go` | Interactive command-line interface |

#### **Database Module** (`/database/`)

- `database.go` - SQLite-based session storage (BuntDB)
- `db_session.go` - Session data models

#### **Parser Module** (`/parser/`)

- `parser.go` - Phishlet YAML configuration parser

#### **Log Module** (`/log/`)

- Custom logging infrastructure

### 2.2 Entry Point

The application entry point is `main.go` (201 lines):

```go
Key initialization flow:
1. Parse command-line flags (-p, -t, -debug, -developer, -c, -v)
2. Load configuration from ~/.evilginx/config.json
3. Initialize database (data.db)
4. Load phishlets from YAML files
5. Start DNS nameserver (port 53)
6. Initialize certificate database with certmagic
7. Start HTTP/HTTPS proxy (ports 80/443)
8. Launch interactive terminal
```

### 2.3 Dependencies

**Key Go Modules:**
```go
- certmagic v0.20.0          // Automatic HTTPS certificates
- goproxy v0.0.0             // HTTP proxy (custom fork)
- miekg/dns v1.1.58          // DNS server
- buntdb v1.1.0              // Embedded database
- go-acme/lego v3.1.0        // LetsEncrypt client
- gorilla/mux v1.7.3         // HTTP routing
- spf13/viper v1.10.1        // Configuration management
- go-resty/resty v2.12.0     // HTTP client
- zap v1.27.0                // Logging
- golang.org/x/crypto        // Cryptographic primitives
```

---

## 3. Advanced Features Analysis

This private dev edition includes 10 major enhancements not found in standard Evilginx:

### 3.1 Machine Learning Bot Detection

**File:** `core/ml_detector.go` (487 lines)

**How it works:**
- Extracts 20+ features from HTTP requests (headers, timing, behavior)
- Uses pre-trained logistic regression model
- Analyzes:
  - HTTP header patterns
  - Request timing intervals
  - Mouse movements and keystrokes
  - TLS version and cipher strength
  - Header ordering
- Returns confidence score (0.0-1.0)
- Configurable threshold (default: 0.75)
- In-memory caching for performance

**Key Features:**
```go
type RequestFeatures struct {
    HeaderCount         int
    UserAgentLength     int
    RequestInterval     float64
    MouseMovements      int
    KeystrokeCount      int
    ScrollDepth         float64
    JA3Hash             string
    TLSVersion          float64
    CipherStrength      int
}
```

### 3.2 JA3/JA3S TLS Fingerprinting

**File:** `core/ja3_fingerprint.go` (477 lines)

**How it works:**
- Captures TLS client hello handshake
- Generates JA3 hash from:
  - TLS version
  - Cipher suites
  - Extensions
  - Elliptic curves
  - Elliptic points
- Compares against known bot signatures
- Detects:
  - Python requests library (hash: b32309a26951912be7dba376398abc3b)
  - Golang HTTP client (hash: c65fcec1b7e7b115c8a2e036cf8d8f78)
  - curl variations
  - Scrapy framework
  - Headless browsers
  - Security scanners

### 3.3 Sandbox Detection

**File:** `core/sandbox_detector.go`

**Detection Methods:**
- VM environment checks (VirtualBox, VMware, QEMU)
- Debugger presence detection
- Analysis tool identification
- Hardware fingerprinting
- Behavioral analysis

**Actions:**
- Block access
- Redirect to honeypot
- Serve fake content
- Log and alert

**Modes:** Passive, Active, Aggressive

### 3.4 Polymorphic JavaScript Engine

**File:** `core/polymorphic_engine.go`

**Mutation Techniques:**
- Variable/function name randomization
- Code structure modification
- Dead code injection
- Control flow obfuscation
- String encoding

**Mutation Levels:** Low, Medium, High, Extreme

### 3.5 Domain Rotation

**File:** `core/domain_rotation.go`

**Strategies:**
- Round-robin: Sequential rotation
- Weighted: Priority-based selection
- Health-based: Availability monitoring
- Random: Unpredictable rotation

**Features:**
- Automatic domain generation
- DNS provider integration (Cloudflare)
- Health monitoring
- Automatic failover
- Certificate management

### 3.6 Traffic Shaping

**File:** `core/traffic_shaper.go`

**Capabilities:**
- Per-IP rate limiting
- Global bandwidth controls
- Geographic-based rules
- Adaptive learning
- DDoS protection
- Priority queuing

**Protection Features:**
- SYN flood protection
- Slowloris mitigation
- Amplification attack detection
- Automatic blacklisting

### 3.7 C2 Channel

**File:** `core/c2_channel.go`

**Features:**
- Multiple transport protocols (HTTPS, DNS)
- End-to-end encryption (AES-256)
- HMAC message authentication
- Command queue management
- Proxy support
- Compression

### 3.8 TLS Interception

**File:** `core/tls_interceptor.go`

**Advanced certificate management:**
- Automated LetsEncrypt retrieval
- Certificate caching
- Custom certificate loading
- Wildcard certificate support

### 3.9 Cloudflare Worker Integration

**Files:** `core/cloudflare_worker.go`, `core/cloudflare_worker_api.go`

**Benefits:**
- IP address protection
- DDoS mitigation
- Global CDN distribution
- SSL/TLS termination
- Rate limiting
- Caching control

### 3.10 Enhanced Telegram Integration

**Files:** `core/telegram.go`, `core/telegram_exporter.go`

**Features:**
- Captured credential alerts
- Session cookie export
- Screenshot delivery
- Campaign statistics
- Error notifications
- Remote control commands

---

## 4. Configuration System

### 4.1 Configuration Files

**Primary Config:** `~/.evilginx/config.json`

The configuration system supports extensive customization:

```json
{
  "general": {
    "domain": "yourdomain.com",
    "external_ipv4": "xxx.xxx.xxx.xxx",
    "bind_ipv4": "0.0.0.0",
    "https_port": 443,
    "dns_port": 53,
    "autocert": true
  },
  "ml_detection": {
    "enabled": true,
    "threshold": 0.75,
    "collect_behavior": true,
    "log_predictions": false
  },
  "ja3_fingerprinting": {
    "enabled": true
  },
  "sandbox_detection": {
    "enabled": true,
    "mode": "active"
  },
  "polymorphic_engine": {
    "enabled": true,
    "mutation_level": "high"
  },
  "traffic_shaping": {
    "enabled": true,
    "per_ip_rate_limit": 100,
    "ddos_protection": true
  },
  "telegram": {
    "enabled": false,
    "bot_token": "YOUR_BOT_TOKEN",
    "chat_id": "YOUR_CHAT_ID"
  },
  "cloudflare": {
    "enabled": false,
    "account_id": "",
    "api_token": ""
  }
}
```

### 4.2 Phishlet System

Phishlets are YAML configuration files that define:
- Target website domains
- Login page paths
- Cookie names to capture
- Authentication tokens
- Sub-domain filters
- JavaScript injections
- Custom POST parameters

---

## 5. Deployment Infrastructure

### 5.1 Automated Installation

**Linux (Ubuntu/Debian):**
- Script: `install.sh`
- Features:
  - Installs Go 1.22
  - Builds from source
  - Configures firewall (UFW)
  - Creates systemd service
  - Stops conflicting services (Apache2, Nginx)
  - Implements security hardening
  - Creates helper commands (evilginx-start, evilginx-stop, etc.)

**Windows (10/11/Server):**
- Script: `install-windows.ps1`
- Features:
  - Installs Go 1.22
  - Builds from source
  - Installs NSSM (service manager)
  - Creates Windows Service
  - Configures Windows Firewall
  - Sets up logging

### 5.2 Service Management

**Linux Commands:**
```bash
evilginx-console    # Interactive configuration
evilginx-start      # Start service
evilginx-stop       # Stop service
evilginx-status     # Check status
evilginx-logs       # View logs
```

### 5.3 Build Scripts

- `Makefile` - Linux/macOS build
- `build.bat` - Windows build
- `build_run.bat` - Windows build and run

---

## 6. Security Considerations

### 6.1 Ethical and Legal Warnings

⚠️ **CRITICAL WARNINGS:**

The project includes extensive legal disclaimers:

1. **Authorization Required:**
   - Written permission from target organization
   - Defined scope of engagement
   - Compliance with local laws
   - Proper data handling protocols

2. **Illegal Use:**
   - Unauthorized use is illegal and unethical
   - Authors not responsible for misuse
   - Criminal penalties for unauthorized access

### 6.2 Operational Security

The project emphasizes:
- Infrastructure isolation
- VPN/proxy chain usage
- Domain privacy protection
- Encrypted data transmission
- Automatic data destruction
- Evidence removal

### 6.3 Detection Evasion

Built-in evasion techniques:
- ML-based bot detection
- TLS fingerprint analysis
- Sandbox environment detection
- Polymorphic code generation
- Traffic pattern randomization
- Geographic restrictions
- IP whitelisting

---

## 7. Code Quality Assessment

### 7.1 Strengths

✅ **Well-structured:** Clear module separation  
✅ **Comprehensive:** 10 advanced features  
✅ **Documented:** Extensive README, guides, and best practices  
✅ **Professional:** Error handling, logging, configuration management  
✅ **Modern:** Uses Go 1.22, current libraries  
✅ **Automated:** Installation scripts, service management  

### 7.2 Code Metrics

- **Total Go files:** 41
- **Core module lines:** ~21,098
- **Longest file:** `http_proxy.go` (2,779 lines)
- **Average file size:** ~515 lines
- **Project size:** 2.7MB

### 7.3 Technical Debt

**Potential concerns:**
- Some files are very long (http_proxy.go: 2,779 lines)
- Vendor dependencies included (could use Go modules exclusively)
- Mix of v2 and v3 module naming (github.com/kgretzky/evilginx2)
- Custom fork of goproxy required

---

## 8. Feature Comparison: Standard vs Private Dev Edition

| Feature | Standard 3.3 | Private Dev Edition |
|---------|--------------|---------------------|
| Basic MITM Proxy | ✅ | ✅ |
| 2FA Bypass | ✅ | ✅ |
| Phishlet System | ✅ | ✅ |
| Gophish Integration | ✅ | ✅ |
| **ML Bot Detection** | ❌ | ✅ |
| **JA3 Fingerprinting** | ❌ | ✅ |
| **Sandbox Detection** | ❌ | ✅ |
| **Polymorphic Engine** | ❌ | ✅ |
| **Domain Rotation** | ❌ | ✅ |
| **Traffic Shaping** | ❌ | ✅ |
| **C2 Channel** | ❌ | ✅ |
| **Advanced Obfuscation** | ❌ | ✅ |
| **Cloudflare Workers** | ❌ | ✅ |
| **Enhanced Telegram** | ❌ | ✅ |

---

## 9. Threat Model

### 9.1 Attack Surface

This tool can be used to attack:
- Corporate login portals (O365, Google Workspace, etc.)
- Social media platforms
- Banking websites
- SaaS applications
- Any web-based authentication system

### 9.2 Defense Mechanisms

Organizations can detect Evilginx by:
- Monitoring for unusual DNS queries
- Checking TLS certificate chains
- Analyzing domain registration dates
- Detecting MITM proxies via timing analysis
- Using hardware tokens (FIDO2/WebAuthn)
- Implementing certificate pinning
- Analyzing JA3 fingerprints from proxy

---

## 10. Documentation Quality

### 10.1 Documentation Files

The project includes comprehensive documentation:

| File | Lines | Purpose |
|------|-------|---------|
| `README.md` | 879 | Main documentation |
| `DEPLOYMENT_GUIDE.md` | 2,164+ | Step-by-step deployment |
| `BEST_PRACTICES.md` | 1,533+ | Operational security guide |
| `CHANGELOG` | 108 | Version history |
| `ISSUE_TEMPLATE.md` | - | Bug reporting template |

### 10.2 Documentation Highlights

✅ **Excellent coverage:**
- Installation guides (Linux, Windows)
- VPS selection and setup
- Domain registration
- Cloudflare configuration
- Security hardening
- Troubleshooting
- Best practices
- Legal considerations

---

## 11. Dependencies and Ecosystem

### 11.1 External Services Required

For full functionality, requires:
- **VPS Provider:** DigitalOcean, Vultr, AWS, etc.
- **Domain Registrar:** Namecheap, GoDaddy, etc.
- **Cloudflare:** For DNS and CDN (free tier works)
- **Telegram:** For notifications (optional)
- **GoPhish:** For campaign management (optional)

### 11.2 Technology Stack

```
┌─────────────────────────────────┐
│   Evilginx 3.3.1 Private Dev   │
├─────────────────────────────────┤
│ Language: Go 1.22               │
│ Database: BuntDB (SQLite-like)  │
│ TLS: certmagic + LetsEncrypt    │
│ Proxy: goproxy (custom fork)    │
│ DNS: miekg/dns                  │
│ Config: Viper (JSON)            │
│ Logging: uber/zap               │
└─────────────────────────────────┘
         ↓
┌─────────────────────────────────┐
│   Operating System Layer        │
├─────────────────────────────────┤
│ Linux: systemd service          │
│ Windows: NSSM service           │
│ Firewall: UFW / Windows FW      │
└─────────────────────────────────┘
         ↓
┌─────────────────────────────────┐
│   Network Layer                 │
├─────────────────────────────────┤
│ Ports: 53 (DNS), 80, 443        │
│ Protocols: HTTP, HTTPS, DNS     │
│ TLS: 1.2, 1.3                   │
└─────────────────────────────────┘
```

---

## 12. Use Cases

### 12.1 Legitimate Uses

✅ **Authorized penetration testing**
- Security awareness training
- Phishing simulation exercises
- Red team engagements
- Security posture assessment

✅ **Research**
- Academic cybersecurity research
- Defensive security development
- Anti-phishing technology testing

### 12.2 Potential Malicious Uses

⚠️ **Illegal activities** (highlighted for awareness):
- Unauthorized credential theft
- Corporate espionage
- Financial fraud
- Identity theft
- Session hijacking

**Note:** All illegal uses are expressly prohibited and punishable by law.

---

## 13. Recommendations

### 13.1 For Red Teams

If using this tool for authorized engagements:

1. **Legal Protection:**
   - Always obtain written authorization
   - Define clear scope and boundaries
   - Document everything
   - Have legal counsel review engagement terms

2. **Operational Security:**
   - Use dedicated infrastructure
   - Implement VPN/proxy chains
   - Enable all evasion features
   - Monitor for detection
   - Plan data destruction

3. **Ethical Conduct:**
   - Minimize harm to targets
   - Protect captured data
   - Report findings responsibly
   - Provide remediation guidance

### 13.2 For Defenders

To protect against Evilginx attacks:

1. **Technical Controls:**
   - Implement FIDO2/WebAuthn hardware tokens
   - Use certificate pinning where possible
   - Monitor for suspicious DNS queries
   - Analyze TLS certificate chains
   - Implement anomaly detection

2. **Organizational Controls:**
   - Security awareness training
   - Phishing simulation exercises
   - Incident response planning
   - User reporting mechanisms

3. **Detection Strategies:**
   - Monitor for newly registered domains
   - Check domain age in login pages
   - Analyze timing patterns
   - Implement JA3 fingerprint monitoring
   - Use threat intelligence feeds

---

## 14. Conclusions

### 14.1 Project Assessment

This is a **highly sophisticated, enterprise-grade phishing framework** with advanced evasion capabilities that significantly exceed the standard Evilginx release.

**Technical Excellence:**
- Well-architected codebase
- Comprehensive feature set
- Professional documentation
- Automated deployment
- Active development

**Security Implications:**
- Extremely effective against traditional defenses
- Bypasses 2FA/MFA via session hijacking
- Advanced evasion of bot detection
- Difficult to detect with standard tools

### 14.2 Risk Assessment

**High Risk Tool:**
- Can bypass most authentication mechanisms
- Evades traditional anti-phishing solutions
- Requires advanced defenses to detect
- Significant legal liability if misused

### 14.3 Final Verdict

**Strengths:**
✅ Comprehensive and professional implementation  
✅ Extensive documentation and guides  
✅ Advanced evasion features  
✅ Multi-platform support  
✅ Active development  

**Concerns:**
⚠️ Extremely powerful tool with dual-use potential  
⚠️ Requires strong ethical guidelines  
⚠️ Legal authorization absolutely required  
⚠️ High technical debt in some modules  

**Recommendation:**
- **For authorized red teams:** Excellent tool with proper safeguards
- **For defenders:** Understand capabilities to build better defenses
- **For general users:** Strictly for educational/authorized use only

---

## 15. Technical Deep Dive Summary

### 15.1 Attack Flow

```
1. Victim receives phishing lure
   ↓
2. Clicks link to attacker's domain (e.g., login.evil-domain.com)
   ↓
3. Evilginx performs MITM:
   - Forwards requests to legitimate site (e.g., login.microsoft.com)
   - Intercepts responses
   - Modifies URLs in real-time
   - Injects JavaScript for behavioral tracking
   ↓
4. Victim enters credentials
   ↓
5. Evilginx captures:
   - Username
   - Password
   - Session cookies
   - 2FA tokens
   ↓
6. Victim completes 2FA
   ↓
7. Evilginx captures authenticated session cookie
   ↓
8. Victim redirected to legitimate site
   ↓
9. Attacker uses captured session cookie to bypass 2FA
```

### 15.2 Evasion Techniques

**Bot Detection Evasion:**
- ML model analyzes behavioral patterns
- Requires mouse movements, keystrokes, realistic timing
- Blocks automated tools, scanners, headless browsers

**TLS Fingerprinting:**
- Identifies automated tools by TLS handshake
- Blocks Python requests, curl, Selenium, etc.

**Sandbox Detection:**
- Detects VMs, analysis tools, debuggers
- Can serve fake content or redirect

**Polymorphic Engine:**
- JavaScript code changes on every request
- Defeats signature-based detection

**Traffic Shaping:**
- Rate limiting prevents automated scanning
- DDoS protection against detection attempts

---

## 16. File Structure

```
Evilginx3/
├── main.go                     # Entry point
├── go.mod, go.sum             # Go modules
├── Makefile                   # Build configuration
├── README.md                  # Main documentation
├── DEPLOYMENT_GUIDE.md        # Deployment instructions
├── BEST_PRACTICES.md          # Security best practices
├── CHANGELOG                  # Version history
├── LICENSE                    # BSD-3 license
├── install.sh                 # Linux installer
├── install-windows.ps1        # Windows installer
├── uninstall.sh              # Linux uninstaller
├── uninstall-windows.ps1     # Windows uninstaller
├── build.bat                 # Windows build script
├── build_run.bat             # Windows build and run
├── run_evilginx.sh           # Linux run script
├── test_install.sh           # Installation test
│
├── core/                     # Core functionality (35 files)
│   ├── http_proxy.go         # Main MITM proxy
│   ├── ml_detector.go        # ML bot detection
│   ├── ja3_fingerprint.go    # TLS fingerprinting
│   ├── sandbox_detector.go   # Sandbox detection
│   ├── polymorphic_engine.go # Code mutation
│   ├── traffic_shaper.go     # Rate limiting
│   ├── domain_rotation.go    # Domain management
│   ├── c2_channel.go         # C2 infrastructure
│   ├── tls_interceptor.go    # TLS management
│   ├── telegram.go           # Telegram integration
│   ├── cloudflare_worker.go  # Cloudflare integration
│   ├── phishlet.go           # Phishing templates
│   ├── session.go            # Session management
│   ├── config.go             # Configuration
│   ├── certdb.go             # Certificate database
│   ├── nameserver.go         # DNS server
│   ├── terminal.go           # CLI interface
│   └── ...                   # 18 more files
│
├── database/                 # Data persistence
│   ├── database.go           # BuntDB wrapper
│   └── db_session.go         # Session storage
│
├── parser/                   # Configuration parsing
│   └── parser.go             # YAML parser
│
├── log/                      # Logging infrastructure
│
├── vendor/                   # Vendored dependencies
│
├── redirectors/              # HTML redirect pages
│
├── deployment/               # Deployment configs
│
├── media/                    # Images and assets
│
└── phishlets/               # Phishing templates (YAML)
```

---

## 17. Additional Resources

### Official Links
- **Original Repository:** https://github.com/kgretzky/evilginx2
- **Documentation:** https://help.evilginx.com
- **Blog:** https://breakdev.org
- **Training:** https://academy.breakdev.org/evilginx-mastery

### Research Papers
- "Evilginx 2.0 - Next Generation of Phishing 2FA Tokens"
- "Evilginx 2.3 - Phisherman's Dream"
- "Evilginx 3.0 - Evilginx Mastery"
- "Evilginx 3.3 - GoPhish Integration"

---

## Document Metadata

**Analysis Date:** November 11, 2025  
**Analyzer:** AI Code Analysis  
**Version Analyzed:** 3.3.1 Private Dev Edition  
**Codebase Snapshot:** /root/.cursor/worktrees/Evilginx3__SSH__root_198.135.48.135_/T1wId  
**Total Files Analyzed:** 41 Go files, 4 documentation files, 2 installation scripts  
**Lines of Code:** ~21,098 (core module only)  

---

**End of Analysis**


