# Automatic Path Detection for Phishlets and Redirectors

## Overview

Evilginx3 now automatically detects the `phishlets` and `redirectors` directories, eliminating the need to specify `-p` and `-t` flags in most cases.

## Changes Implemented

### Previous Behavior

Previously, when running the executable from the `build/` directory, you had to specify paths:

```bash
sudo ./build/evilginx -p ./phishlets -t ./redirectors
```

This was because the executable looked for directories relative to its own location (`build/phishlets` and `build/redirectors`), which didn't exist.

### New Behavior

The executable now intelligently searches multiple locations for the required directories:

#### Phishlets Search Order:
1. **`{exe_dir}/phishlets`** - Same directory as executable
2. **`{exe_dir}/../phishlets`** - Parent directory (handles `build/evilginx` case)
3. **`/usr/share/evilginx/phishlets/`** - System installation path
4. If none found, displays error with all attempted paths

#### Redirectors Search Order:
1. **`{exe_dir}/redirectors`** - Same directory as executable
2. **`{exe_dir}/../redirectors`** - Parent directory (handles `build/evilginx` case)
3. **`/usr/share/evilginx/redirectors/`** - System installation path
4. If none found, falls back to `{exe_dir}/../redirectors` (will be created if needed)

## Usage Examples

### Running from Project Root

```bash
# No flags needed!
sudo ./build/evilginx

# Or from within build directory
cd build
sudo ./evilginx
```

### Running from Anywhere

If you copy the executable to a different location:

```bash
# Copy executable
cp build/evilginx /usr/local/bin/

# Copy phishlets and redirectors to system location
sudo mkdir -p /usr/share/evilginx
sudo cp -r phishlets /usr/share/evilginx/
sudo cp -r redirectors /usr/share/evilginx/

# Run from anywhere
sudo evilginx
```

### Manual Override (Still Supported)

You can still manually specify paths if needed:

```bash
# Override both paths
sudo ./build/evilginx -p /custom/phishlets -t /custom/redirectors

# Override just phishlets
sudo ./build/evilginx -p /custom/phishlets

# Override just redirectors
sudo ./build/evilginx -t /custom/redirectors
```

## Benefits

### 1. Convenience
No need to type long flag commands every time you run Evilginx3.

### 2. Flexibility
Works in multiple scenarios:
- Running from `build/` directory
- Running from project root
- System-wide installation
- Custom installations

### 3. Better Error Messages
If directories aren't found, you see all attempted locations:

```
phishlets directory not found. Tried:
  - C:\Users\user\Desktop\git\Evilginx3\build\phishlets
  - C:\Users\user\Desktop\git\Evilginx3\phishlets
  - /usr/share/evilginx/phishlets/
Please specify with -p flag
```

### 4. Backwards Compatible
All existing scripts and commands using `-p` and `-t` flags continue to work exactly as before.

## Technical Details

### Path Resolution

The code uses `filepath.Clean()` to resolve `..` references, ensuring clean absolute paths regardless of how the executable is invoked.

### Search Logic

```go
// Simplified search logic
if *phishlets_dir == "" {
    // Try relative to executable
    if exists(exe_dir + "/phishlets") {
        use that
    } else if exists(exe_dir + "/../phishlets") {
        use that (handles build/ case)
    } else if exists("/usr/share/evilginx/phishlets/") {
        use that (system install)
    } else {
        error with all attempted paths
    }
}
```

### Modified File

- **`main.go`** (lines 52-90): Enhanced path detection logic

## Common Scenarios

### Scenario 1: Development (Running from project)

```bash
git clone <repo>
cd Evilginx3
./build.bat  # or make
sudo ./build/evilginx  # No flags needed! ✅
```

### Scenario 2: System Installation

```bash
# Build
./build.bat

# Install
sudo cp build/evilginx /usr/local/bin/
sudo mkdir -p /usr/share/evilginx
sudo cp -r phishlets /usr/share/evilginx/
sudo cp -r redirectors /usr/share/evilginx/

# Run from anywhere
cd ~
sudo evilginx  # No flags needed! ✅
```

### Scenario 3: Custom Setup

```bash
# You have a special directory structure
sudo ./build/evilginx -p /opt/my-phishlets -t /opt/my-redirectors
```

## Testing

To verify the path detection is working:

```bash
# Test 1: From project root
sudo ./build/evilginx -v
# Should show version (confirms it found phishlets)

# Test 2: From build directory
cd build
sudo ./evilginx -v
# Should show version (confirms parent directory search works)

# Test 3: Check what paths were detected
sudo ./build/evilginx
# On startup, it will log: "loading phishlets from: <path>"
```

## Troubleshooting

### "phishlets directory not found" Error

If you see this error, the automatic detection failed. The error message shows all attempted locations. Common fixes:

1. **Ensure directories exist**:
   ```bash
   ls -la phishlets
   ls -la redirectors
   ```

2. **Check your current directory**:
   ```bash
   pwd
   # Make sure you're in the right place
   ```

3. **Use manual flags**:
   ```bash
   sudo ./build/evilginx -p ./phishlets -t ./redirectors
   ```

### Paths Not What You Expected

The executable will log the detected paths on startup:

```
[12:34:56] [inf] loading phishlets from: /path/to/phishlets
```

If this isn't the path you want, use the `-p` flag to override.

## Implementation Date

**November 9, 2025** - Implemented as part of Evilginx3 3.3.1+

## Related Files

- `main.go` - Main entry point with path detection logic
- `phishlets/` - Directory containing all phishlet YAML files
- `redirectors/` - Directory containing HTML redirector pages

---

**Summary**: You can now run `sudo ./build/evilginx` without any flags, and it will automatically find your phishlets and redirectors directories. Manual override flags (`-p` and `-t`) are still supported for custom setups.

