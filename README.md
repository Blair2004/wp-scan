# WordPress Malware Scanner

A powerful command-line utility for detecting, scanning, and remediating malware in WordPress installations. This tool helps identify infected files, provides multiple cleanup strategies, and can automatically reinstall compromised WordPress core files, plugins, and themes.

## Features

### 🔍 Detection & Scanning
- **Automatic WordPress Discovery**: Recursively scans directories to find all WordPress installations
- **Malware Pattern Detection**: Uses 30+ high-risk and suspicious patterns to identify infected files
- **Severity Classification**: Categorizes threats as high, medium, or low severity
- **Comprehensive Reporting**: Generates detailed JSON reports with vulnerability information
- **Installation Caching**: Stores detected WordPress sites with version, plugin, and theme information

### 🛠️ Remediation Options
- **Delete**: Permanently removes infected files (with automatic backup)
- **Quarantine**: Moves infected files to a `.quarantined` directory for review
- **Comment Out**: Wraps malicious code with warning comments and `die()` statements
- **Selective Cleaning**: Target specific severity levels (high, medium, low)

### 🔄 Reinstallation Features
- **WordPress Core Reinstall**: Replace core files with fresh copies from WordPress.org
- **Plugin Reinstall**: Reinstall all free plugins or target specific ones
- **Theme Reinstall**: Reinstall all free themes or target specific ones
- **Complete Rebuild**: Reinstall core, plugins, and themes in one operation
- **Smart Detection**: Automatically skips premium plugins/themes
- **Version Control**: Install specific WordPress versions or use current version
- **Infected-Only Mode**: Only reinstall components identified as infected

### 🔐 Safety Features
- **Automatic Backups**: Creates backups before all destructive operations
- **Premium Plugin/Theme Protection**: Never touches premium/non-repository items
- **Quarantine Tracking**: Maintains records of quarantined files in cache
- **Force Mode**: Option to reinstall even if current version matches
- **Dry Run**: Scan without making any changes

## Requirements

- PHP 7.4 or higher (CLI mode)
- Linux/Unix environment
- Read/write permissions on target directories
- `curl` or `wget` for downloading WordPress files

## Installation

Clone or download the script to your system:

```bash
git clone <repository-url>
cd scan
chmod +x scan.php
```

## Quick Start

### 1. Detect WordPress Installations

First, scan your server to find and cache all WordPress installations:

```bash
php scan.php --detect --path /var/www
```

This creates a `cached.json` file with details about each installation.

### 2. List Detected Sites

View all detected WordPress installations:

```bash
php scan.php --list
```

### 3. Scan for Malware

Perform a malware scan (dry run):

```bash
php scan.php --dry --path /var/www
```

This generates a `scan_report.json` file with infected file details.

### 4. Clean Infected Files

Apply fixes based on severity:

```bash
# Delete high-severity threats
php scan.php --delete-high-severity --website example.com

# Quarantine medium-severity files for review
php scan.php --quarantine-medium-severity --website example.com

# Comment out low-severity code
php scan.php --comment-low-severity --website example.com
```

### 5. Reinstall Compromised Components

```bash
# Reinstall WordPress core
php scan.php --reinstall-core --website example.com

# Reinstall all free plugins
php scan.php --reinstall-plugins --website example.com

# Reinstall everything
php scan.php --reinstall-all --website example.com
```

## Usage

### Detection Commands

```bash
# Detect WordPress installations and cache information
php scan.php --detect --path /foo/bar

# List detected WordPress installations
php scan.php --list

# Use custom cache file
php scan.php --list --cached custom.json
```

### Scanning Commands

```bash
# Scan for infected files (uses cached installations)
php scan.php --dry

# Scan specific path
php scan.php --dry --path /var/www/html

# Use custom cache file
php scan.php --dry --cached custom.json
```

### Fix Commands

All fix commands require `--website` to specify which installation to target:

#### Delete Actions
```bash
# Delete files with high severity vulnerabilities
php scan.php --delete-high-severity --website example.com

# Delete files with medium severity vulnerabilities
php scan.php --delete-medium-severity --website example.com

# Delete files with low severity vulnerabilities
php scan.php --delete-low-severity --website example.com
```

#### Quarantine Actions
```bash
# Quarantine high severity files
php scan.php --quarantine-high-severity --website example.com

# Quarantine medium severity files
php scan.php --quarantine-medium-severity --website example.com

# Quarantine low severity files
php scan.php --quarantine-low-severity --website example.com
```

#### Comment Actions
```bash
# Comment out high severity code
php scan.php --comment-high-severity --website example.com

# Comment out medium severity code
php scan.php --comment-medium-severity --website example.com

# Comment out low severity code
php scan.php --comment-low-severity --website example.com
```

### Reinstall Commands

```bash
# Reinstall WordPress core files
php scan.php --reinstall-core --website example.com

# Reinstall with specific WordPress version
php scan.php --reinstall-core --website example.com --wp 6.4.2

# Reinstall all free plugins
php scan.php --reinstall-plugins --website example.com

# Reinstall specific plugin
php scan.php --reinstall-plugin woocommerce --website example.com

# Reinstall all free themes
php scan.php --reinstall-themes --website example.com

# Reinstall specific theme
php scan.php --reinstall-theme twentytwentyfour --website example.com

# Reinstall everything (core + plugins + themes)
php scan.php --reinstall-all --website example.com

# Force reinstall even if versions match
php scan.php --reinstall-plugins --website example.com --force

# Only reinstall infected plugins/themes
php scan.php --reinstall-plugins --website example.com --only-infected --report scan_report.json
```

## Command-Line Options

### Modes
- `--detect` - Detect WordPress installations and cache info
- `--list` - List detected WordPress installations from cache
- `--dry` - Perform a malware scan without making changes

### Fix Actions (require `--website`)
- `--delete-high-severity` - Delete files with high severity vulnerabilities
- `--delete-medium-severity` - Delete files with medium severity vulnerabilities
- `--delete-low-severity` - Delete files with low severity vulnerabilities
- `--quarantine-high-severity` - Quarantine high severity files
- `--quarantine-medium-severity` - Quarantine medium severity files
- `--quarantine-low-severity` - Quarantine low severity files
- `--comment-high-severity` - Comment out high severity code
- `--comment-medium-severity` - Comment out medium severity code
- `--comment-low-severity` - Comment out low severity code

### Reinstall Actions (require `--website`)
- `--reinstall-core` - Reinstall WordPress core files
- `--reinstall-plugins` - Reinstall all free plugins
- `--reinstall-plugin <name>` - Reinstall specific plugin
- `--reinstall-themes` - Reinstall all free themes
- `--reinstall-theme <name>` - Reinstall specific theme
- `--reinstall-all` - Reinstall core + plugins + themes

### Options
- `--path <path>` - Path to scan for WordPress installations
- `--report <file>` - JSON report file to use (default: `scan_report.json`)
- `--cached <file>` - Cache file path (default: `cached.json`)
- `--website <domain>` - Website domain or identifier
- `--wp <version>` - WordPress version to install (default: current)
- `--force` - Force reinstall even if version is current
- `--only-infected` - Only reinstall infected plugins/themes (requires `--report`)
- `--no-backup` - Skip backup creation (not recommended)

## Malware Detection Patterns

The scanner detects over 30 malware patterns including:

### High-Risk Patterns
- `eval(base64_decode())` - Obfuscated code execution
- `eval(gzinflate())` - Compressed malicious code
- System execution functions (`system`, `exec`, `shell_exec`, `passthru`)
- `preg_replace` with `/e` modifier (PHP code execution)
- Long base64 encoded strings (500+ chars)
- Hex/octal obfuscation
- Variable function calls
- Cookie/request backdoors
- File manipulation with suspicious patterns
- WordPress config injection attempts

### Suspicious Patterns
- `base64_decode()` usage
- `gzinflate()` usage
- `str_rot13()` usage
- `eval()` usage
- Remote file inclusion patterns

## Output Files

### cached.json
Contains detected WordPress installations with:
- Installation path and domain
- WordPress version
- PHP version
- List of plugins (with premium detection)
- List of themes (with premium detection)
- Quarantined files tracking

### scan_report.json
Contains scan results with:
- Scan metadata (date, duration, statistics)
- Per-installation infected files
- Vulnerability details with severity levels
- Pattern matches with line numbers
- File paths and sizes

## Workflow Examples

### Example 1: Complete Site Cleanup

```bash
# Step 1: Detect all WordPress sites
php scan.php --detect --path /var/www

# Step 2: List detected sites
php scan.php --list

# Step 3: Scan for malware
php scan.php --dry

# Step 4: Delete high severity threats
php scan.php --delete-high-severity --website example.com

# Step 5: Quarantine medium severity for review
php scan.php --quarantine-medium-severity --website example.com

# Step 6: Reinstall WordPress core
php scan.php --reinstall-core --website example.com

# Step 7: Reinstall infected plugins only
php scan.php --reinstall-plugins --website example.com --only-infected --report scan_report.json
```

### Example 2: Quick Single Site Scan

```bash
# Scan and clean a single site
php scan.php --dry --path /var/www/example.com
php scan.php --delete-high-severity --website example.com
php scan.php --reinstall-core --website example.com
```

### Example 3: Bulk Reinstall

```bash
# Force reinstall everything on a compromised site
php scan.php --reinstall-all --website example.com --force
```

## Safety Notes

⚠️ **Important Safety Information**

1. **Always test on staging first** - Run the scanner on a staging environment before production
2. **Backups are automatic** - The tool creates backups before destructive operations, but maintain your own backups
3. **Premium plugins/themes** - Premium items are automatically detected and skipped during reinstalls
4. **Review quarantined files** - Inspect quarantined files in `.quarantined` directories before permanent deletion
5. **False positives** - Some legitimate code may trigger low-severity warnings (review before deleting)
6. **Database safety** - This tool only handles files, not database infections
7. **Permissions** - Ensure the script has proper read/write permissions
8. **Website parameter** - The `--website` value should match the domain field from `--list` output

## Troubleshooting

### "No cached installations found"
Run detection first: `php scan.php --detect --path /your/path`

### "Website not found in cache"
Use `php scan.php --list` to see available websites, then use the exact domain shown

### "Permission denied" errors
Ensure the script has read/write permissions on the target directories

### Premium plugins are reinstalled
Check the plugin detection logic - only free plugins from WordPress.org should be reinstalled

### Files still infected after cleanup
Some malware may have database components. Check database tables for malicious entries.

## Technical Details

### File Structure
- `scan.php` - Main scanner class and CLI handler
- `cached.json` - Installation cache (auto-generated)
- `scan_report.json` - Scan results (auto-generated)
- `.quarantined/` - Quarantined files directory (auto-generated)

### Backup Locations
Backups are stored in:
- `.backup_[timestamp]/` - Directory-level backups
- `[filename].backup_[timestamp]` - Individual file backups

### Cache File Format
```json
{
  "detected_date": "2026-01-07 12:00:00",
  "installations": [
    {
      "path": "/var/www/example.com",
      "domain": "example.com",
      "wp_version": "6.4.2",
      "php_version": "8.1.0",
      "plugins": [...],
      "themes": [...],
      "quarantined_files": [...]
    }
  ]
}
```

## Contributing

Contributions are welcome! Areas for improvement:
- Additional malware patterns
- Database scanning capabilities
- Multi-threaded scanning
- Web-based UI
- Integration with security APIs

## License

[Specify your license here]

## Support

For issues, questions, or contributions, please [contact information or repository link].

---

**Disclaimer**: This tool is provided as-is. Always maintain backups and test in non-production environments first. The authors are not responsible for any data loss or damage resulting from use of this tool.
