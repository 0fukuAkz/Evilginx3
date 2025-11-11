<p align="center">
  <img alt="Evilginx2 Logo" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/evilginx2-logo-512.png" height="160" />
  <p align="center">
    <img alt="Evilginx2 Title" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/evilginx2-title-black-512.png" height="60" />
  </p>
</p>

# Evilginx 3.3.1 - Private Dev Edition

**Evilginx** is a man-in-the-middle attack framework used for phishing login credentials along with session cookies, which in turn allows to bypass 2-factor authentication protection.

This **Private Development Edition** includes advanced evasion, detection, and operational features not available in the standard release.

**Modified by:** AKaZA (Akz0fuku)  
**Original Author:** Kuba Gretzky ([@mrgretzky](https://twitter.com/mrgretzky))  
**Version:** 3.3.1 - Private Dev Edition

<p align="center">
  <img alt="Screenshot" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/screen.png" height="320" />
</p>

## 🚨 Disclaimer

This tool is designed for **AUTHORIZED PENETRATION TESTING AND RED TEAM ENGAGEMENTS ONLY**. Unauthorized use of this tool is illegal and unethical. The authors and contributors are not responsible for misuse or damage caused by this tool.

**Legal Requirements:**
- Written authorization from target organization
- Defined scope of engagement
- Compliance with local laws and regulations
- Proper data handling and destruction protocols

Evilginx should be used only in legitimate penetration testing assignments with written permission from to-be-phished parties.

---

## 📚 Table of Contents

- [What's New in Private Dev Edition](#whats-new-in-private-dev-edition)
- [Advanced Features](#advanced-features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Complete Deployment Guide](#complete-deployment-guide)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [Official Resources](#official-resources)
- [License](#license)

---

## 🚀 What's New in Private Dev Edition

This private development edition extends the standard Evilginx 3.3 with enterprise-grade features for advanced red team operations:

### Core Enhancements

✅ **Machine Learning Bot Detection** - AI-powered detection evasion  
✅ **JA3/JA3S Fingerprinting** - TLS fingerprint analysis and blocking  
✅ **Sandbox Detection** - VM and analysis tool detection  
✅ **Polymorphic JavaScript Engine** - Dynamic code mutation  
✅ **Domain Rotation** - Automated domain switching  
✅ **Traffic Shaping** - Adaptive rate limiting and DDoS protection  
✅ **C2 Channel** - Encrypted command and control  
✅ **TLS Interception** - Advanced certificate management  
✅ **Cloudflare Worker Integration** - Proxy bypass capabilities  
✅ **Enhanced Telegram Integration** - Real-time notifications  
✅ **Advanced Obfuscation** - Multi-layer code obfuscation

---

## 🛡️ Advanced Features

### 1. Machine Learning Bot Detection

Intelligent bot detection using behavioral analysis and feature extraction.

**Features:**
- HTTP header analysis
- Timing pattern recognition
- Behavioral metrics (mouse movements, keystrokes, scroll depth)
- Network fingerprinting
- Confidence-based scoring
- Automatic caching and learning

**Configuration:**
```json
{
  "ml_detection": {
    "enabled": true,
    "threshold": 0.75,
    "learning_mode": true,
    "cache_duration": 30
  }
}
```

### 2. JA3/JA3S TLS Fingerprinting

Detect and block automated tools based on TLS handshake fingerprints.

**Detected Tools:**
- Python requests library
- Golang HTTP clients
- curl variations
- Scrapy framework
- Headless browsers
- Security scanners

**Features:**
- Real-time fingerprint matching
- Known bot signature database
- Custom signature addition
- Confidence scoring

### 3. Sandbox Detection

Multi-layer detection of analysis environments.

**Detection Methods:**
- VM environment detection
- Debugger presence
- Analysis tool identification
- Behavioral analysis
- Hardware fingerprinting

**Actions:**
- Block access
- Redirect to honeypot
- Serve fake content
- Log and alert

**Modes:**
- **Passive**: Silent detection
- **Active**: Challenge-response tests
- **Aggressive**: Multi-stage verification

### 4. Polymorphic JavaScript Engine

Dynamic code mutation to evade signature-based detection.

**Mutation Techniques:**
- Variable/function name randomization
- Code structure modification
- Dead code injection
- Control flow obfuscation
- String encoding

**Mutation Levels:**
- **Low**: Basic variable renaming
- **Medium**: Structure modification + renaming
- **High**: Advanced obfuscation + control flow changes
- **Extreme**: Maximum mutation with semantic preservation

### 5. Domain Rotation

Automated domain management and rotation.

**Strategies:**
- **Round-robin**: Sequential rotation
- **Weighted**: Priority-based selection
- **Health-based**: Availability monitoring
- **Random**: Unpredictable rotation

**Features:**
- Automatic domain generation
- DNS provider integration (Cloudflare)
- Health monitoring
- Automatic failover
- Certificate management

### 6. Traffic Shaping

Intelligent traffic management and protection.

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

### 7. C2 Channel

Encrypted command and control infrastructure.

**Features:**
- Multiple transport protocols (HTTPS, DNS)
- End-to-end encryption
- HMAC message authentication
- Command queue management
- Proxy support
- Compression

**Security:**
- AES-256 encryption
- Perfect forward secrecy
- Anti-replay protection
- Traffic obfuscation

### 8. Cloudflare Worker Integration

Deploy phishing infrastructure behind Cloudflare Workers.

**Benefits:**
- IP address protection
- DDoS mitigation
- Global CDN distribution
- SSL/TLS termination
- Rate limiting
- Caching control

### 9. Enhanced Telegram Integration

Real-time notifications and data exfiltration.

**Features:**
- Captured credential alerts
- Session cookie export
- Screenshot delivery
- Campaign statistics
- Error notifications
- Remote control commands

### 10. Advanced Obfuscation

Multi-layer code and traffic obfuscation.

**Techniques:**
- JavaScript obfuscation
- HTML structure randomization
- CSS class name mutation
- Network traffic padding
- Timing randomization

---

## ⚡ Quick Start

### Prerequisites

**For Linux (VPS):**
- Ubuntu 20.04+ or Debian 11+
- Domain name
- Cloudflare account (free tier works)
- Root or sudo access

**For Windows:**
- Windows 10/11 or Windows Server 2016+
- Administrator access
- Domain name
- Cloudflare account (free tier works)

### 🎯 One-Click Installation

#### Linux (Ubuntu/Debian) - Recommended for Production

```bash
# Clone repository
git clone https://github.com/yourusername/evilginx3.git
cd evilginx3

# Run automated installer
chmod +x install.sh
sudo ./install.sh
```

**The installer automatically:**
- ✅ Installs all dependencies (Go, tools, etc.)
- ✅ Builds Evilginx from source
- ✅ Stops conflicting services (Apache2, Nginx)
- ✅ Configures firewall (UFW)
- ✅ Creates systemd service with auto-start
- ✅ Sets up helper commands
- ✅ Implements security hardening

**See [INSTALLATION_QUICK_START.md](INSTALLATION_QUICK_START.md) for complete Linux installation guide**

#### Windows (Windows 10/11/Server)

```powershell
# Open PowerShell as Administrator
# Navigate to Evilginx directory
cd C:\Users\user\Desktop\git\Evilginx3

# Run Windows installer
.\install-windows.ps1
```

**The Windows installer automatically:**
- ✅ Installs Go 1.22 (if not present)
- ✅ Builds Evilginx from source
- ✅ Installs NSSM (service manager)
- ✅ Creates Windows Service with auto-start
- ✅ Configures Windows Firewall
- ✅ Creates helper commands
- ✅ Sets up logging

**See [WINDOWS_INSTALLATION_GUIDE.md](WINDOWS_INSTALLATION_GUIDE.md) for complete Windows installation guide**

### Manual Installation

```bash
# Clone repository
git clone https://github.com/yourusername/evilginx3.git
cd evilginx3

# Build
make

# Run
sudo ./build/evilginx -p ./phishlets
```

### First-Time Setup

```bash
# Start Evilginx
sudo ./build/evilginx -p ./phishlets

# In Evilginx terminal:
config domain yourdomain.com
config ipv4 your.vps.ip

# Enable a phishlet
phishlets hostname o365 login.yourdomain.com
phishlets enable o365

# Create a lure
lures create o365
lures get-url 0
```

**For complete deployment guide, see [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)**

---

## 📦 Installation

### Option 1: One-Click Automated Installer (Recommended) 🎯

#### Linux (Ubuntu/Debian) - Production Deployment

**Complete system setup with one command:**

```bash
git clone https://github.com/yourusername/evilginx3.git
cd evilginx3
chmod +x install.sh
sudo ./install.sh
```

**Features:**
- ✅ Installs all dependencies automatically
- ✅ Builds from source
- ✅ Configures firewall (ports 22, 53, 80, 443)
- ✅ Creates systemd service with auto-start
- ✅ Stops conflicting services (Apache2, Nginx)
- ✅ Implements security hardening
- ✅ Creates helper commands (`evilginx-start`, `evilginx-stop`, etc.)
- ✅ Sets up fail2ban protection

**Post-installation:**
```bash
evilginx-console    # Configure interactively
evilginx-start      # Start as system service
evilginx-status     # Check status
evilginx-logs       # Monitor logs
```

**See:** [INSTALLATION_QUICK_START.md](INSTALLATION_QUICK_START.md) for complete Linux guide

#### Windows (Windows 10/11/Server)

**Windows Service installation:**

```powershell
# Open PowerShell as Administrator
cd C:\Users\user\Desktop\git\Evilginx3
.\install-windows.ps1
```

**Features:**
- ✅ Installs Go 1.22 automatically
- ✅ Builds from source
- ✅ Installs NSSM (service manager)
- ✅ Creates Windows Service with auto-start
- ✅ Configures Windows Firewall (ports 53, 80, 443)
- ✅ Creates helper commands (`evilginx-start`, `evilginx-stop`, etc.)
- ✅ Sets up logging

**Post-installation:**
```powershell
evilginx-console    # Configure interactively
evilginx-start      # Start Windows service
evilginx-status     # Check service status
evilginx-logs       # Monitor logs
```

**See:** [WINDOWS_INSTALLATION_GUIDE.md](WINDOWS_INSTALLATION_GUIDE.md) for complete Windows guide

### Option 2: Build from Source (Manual)

**Requirements:**
- Go 1.22 or higher
- git

```bash
# Install Go
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Clone and build
git clone https://github.com/yourusername/evilginx3.git
cd evilginx3
go mod download
go build -o build/evilginx main.go

# Make executable
chmod +x build/evilginx
```

### Option 3: Quick Build

```bash
# Linux/macOS
make

# Windows
build.bat
```

### Option 4: Docker (Experimental)

```bash
# Build image
docker build -t evilginx3 .

# Run container
docker run -it -p 443:443 -p 80:80 -p 53:53/udp \
  -v $(pwd)/phishlets:/app/phishlets \
  -v ~/.evilginx:/root/.evilginx \
  evilginx3
```

---

## 📖 Complete Deployment Guide

For a comprehensive, step-by-step guide covering:

- VPS selection and setup
- Domain registration
- Cloudflare configuration
- SSL/TLS certificates
- Security hardening
- Feature configuration
- Phishlet creation
- Lure deployment
- Operational security
- Monitoring and logging

**See the complete guide:** [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)

---

## ⚙️ Configuration

### Basic Configuration

Configuration is stored in `~/.evilginx/config.json`:

```json
{
  "server_bind_ipv4": "0.0.0.0",
  "external_ipv4": "your.vps.ip",
  "https_port": 443,
  "dns_port": 53,
  "base_domain": "yourdomain.com",
  "autocert": true
}
```

### Advanced Features Configuration

```json
{
  "ml_detection": {
    "enabled": true,
    "threshold": 0.75
  },
  "ja3_fingerprinting": {
    "enabled": true,
    "block_known_bots": true
  },
  "sandbox_detection": {
    "enabled": true,
    "mode": "active",
    "action_on_detection": "redirect"
  },
  "polymorphic_engine": {
    "enabled": true,
    "mutation_level": "high",
    "seed_rotation": 15
  },
  "domain_rotation": {
    "enabled": false,
    "strategy": "health-based"
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
  }
}
```

### DNS Provider Setup (Cloudflare)

```json
{
  "dns_provider": {
    "provider": "cloudflare",
    "api_key": "your_api_key",
    "email": "your@email.com",
    "enabled": true
  }
}
```

---

## 💡 Usage Examples

### Basic Phishing Campaign

```bash
# Start Evilginx
sudo ./build/evilginx -p ./phishlets

# Configure domain and IP
config domain example.com
config ipv4 123.45.67.89

# Setup phishlet
phishlets hostname o365 login.example.com
phishlets enable o365

# Create lure
lures create o365
lures edit 0 redirect_url https://office.com

# Get phishing URL
lures get-url 0
```

### Advanced Campaign with All Features

```bash
# Enable ML bot detection
config ml_detection on
config ml_threshold 0.8

# Enable JA3 fingerprinting
config ja3_detection on

# Enable sandbox detection
config sandbox_detection on
config sandbox_mode aggressive

# Enable polymorphic engine
config polymorphic on
config mutation_level extreme

# Enable traffic shaping
config traffic_shaping on
config rate_limit 50

# Setup Telegram notifications
config telegram_token YOUR_BOT_TOKEN
config telegram_chat YOUR_CHAT_ID
config telegram on

# Create sophisticated lure
lures create o365
lures edit 0 redirect_url https://office.com
lures edit 0 og_title "Important Security Update"
lures edit 0 og_description "Please verify your account"
lures edit 0 og_image https://example.com/image.jpg
```

### Domain Rotation Setup

```bash
# Enable domain rotation
config domain_rotation on
config rotation_strategy health-based
config rotation_interval 60

# Add domains
domains add primary.com
domains add backup1.com
domains add backup2.com

# Start health monitoring
domains health_check on
```

---

## 🎯 Best Practices

### Operational Security

1. **Infrastructure Isolation**
   - Use dedicated VPS for each campaign
   - Separate C2 infrastructure
   - Use VPN or proxy chains
   - Burn infrastructure after engagement

2. **Domain Management**
   - Use privacy protection
   - Register through different registrars
   - Age domains before use
   - Use realistic domain names

3. **Traffic Management**
   - Enable rate limiting
   - Use geographic restrictions
   - Implement IP whitelisting for testing
   - Monitor for security researchers

4. **Data Protection**
   - Encrypt captured credentials
   - Use secure communication channels
   - Implement automatic data destruction
   - Follow data retention policies

### Detection Evasion

1. **Enable All Protection Features**
   ```bash
   config ml_detection on
   config ja3_detection on
   config sandbox_detection on
   config polymorphic on
   config traffic_shaping on
   ```

2. **Randomization**
   - Enable polymorphic engine
   - Rotate domains regularly
   - Vary traffic patterns
   - Randomize response timing

3. **Legitimacy**
   - Use realistic phishing scenarios
   - Proper SSL certificates
   - Cloudflare protection
   - Professional design

### Campaign Management

1. **Testing**
   - Test all features before deployment
   - Verify credential capture
   - Test on multiple browsers
   - Validate mobile compatibility

2. **Monitoring**
   - Enable Telegram notifications
   - Monitor logs regularly
   - Track success rates
   - Watch for anomalies

3. **Cleanup**
   - Remove lures after campaign
   - Delete captured data securely
   - Destroy infrastructure
   - Clear logs

### Legal and Ethical

1. **Authorization**
   - Always get written permission
   - Define clear scope
   - Document everything
   - Follow rules of engagement

2. **Data Handling**
   - Minimize data collection
   - Encrypt all data
   - Secure transmission
   - Proper destruction

3. **Reporting**
   - Detailed documentation
   - Clear methodology
   - Recommendations
   - Remediation guidance

---

## 🔧 Troubleshooting

### Common Issues

**Issue: Port 443 already in use**
```bash
# Check what's using the port
sudo lsof -i :443

# Stop conflicting service
sudo systemctl stop apache2  # or nginx
```

**Issue: DNS not resolving**
```bash
# Check DNS configuration
dig @your.vps.ip yourdomain.com

# Verify nameservers
whois yourdomain.com | grep "Name Server"
```

**Issue: Certificate errors**
```bash
# Disable autocert and use manual certificates
config autocert off

# Or enable developer mode for self-signed certs
./build/evilginx -developer -p ./phishlets
```

**Issue: ML detection false positives**
```bash
# Lower threshold
config ml_threshold 0.6

# Enable learning mode
config ml_learning on
```

**Issue: Sessions not capturing**
```bash
# Enable debug logging
./build/evilginx -debug -p ./phishlets

# Check phishlet configuration
phishlets get-hosts o365
```

### Debug Mode

```bash
# Run with debug output
./build/evilginx -debug -p ./phishlets

# Check logs
tail -f ~/.evilginx/logs/evilginx.log
```

### Performance Optimization

```bash
# Increase system limits
ulimit -n 65535

# Optimize traffic shaping
config burst_size 200
config queue_size 1000

# Enable caching
config ml_cache on
config polymorphic_cache on
```

---

## 📚 Official Resources

### Original Evilginx

- **Documentation**: https://help.evilginx.com
- **Blog**: https://breakdev.org
- **Training**: [Evilginx Mastery Course](https://academy.breakdev.org/evilginx-mastery)
- **Gophish Integration**: https://github.com/kgretzky/gophish/

### Write-ups

- [Evilginx 2.0 - Release](https://breakdev.org/evilginx-2-next-generation-of-phishing-2fa-tokens)
- [Evilginx 2.3 - Phisherman's Dream](https://breakdev.org/evilginx-2-3-phishermans-dream/)
- [Evilginx 3.0](https://breakdev.org/evilginx-3-0-evilginx-mastery/)
- [Evilginx 3.3 - GoPhish Integration](https://breakdev.org/evilginx-3-3-go-phish/)

---

## 📋 Feature Comparison

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

## 🤝 Contributing

This is a private development fork. For the original project:
- **Original Repository**: https://github.com/kgretzky/evilginx2
- **Original Author**: Kuba Gretzky ([@mrgretzky](https://twitter.com/mrgretzky))

---

## 📄 License

**BSD-3 Clause License**

Copyright (c) 2018-2023 Kuba Gretzky. All rights reserved.  
Private modifications by AKaZA (Akz0fuku).

See [LICENSE](LICENSE) file for full license text.

---

## ⚠️ Legal Notice

**This tool is provided for educational and authorized testing purposes only.**

By using this software, you agree to:
- Only use it with explicit written authorization
- Comply with all applicable laws and regulations
- Accept full responsibility for your actions
- Not hold the authors liable for misuse

**Unauthorized access to computer systems is illegal.** Use responsibly.

---

## 📞 Support

**For the original Evilginx:**
- Documentation: https://help.evilginx.com
- Author does NOT provide phishlet creation support

**For this private edition:**
- Review [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for setup help
- Check [Troubleshooting](#troubleshooting) section
- Enable debug mode for detailed logs

---

**Remember: With great power comes great responsibility. Use ethically and legally.**
