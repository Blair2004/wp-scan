<?php
/**
 * WordPress Malware Scanner
 * 
 * Scans directories for WordPress installations and detects infected files.
 * 
 * Usage:
 *   php scan.php --dry --path /foo/bar
 *   php scan.php --delete-infected --report report.json
 *   php scan.php --rename-infected --report report.json
 */

class WordPressMalwareScanner {
    
    private $malwarePatterns = [];
    private $suspiciousPatterns = [];
    private $report = [];
    private $scannedFiles = 0;
    private $infectedFiles = 0;
    private $startTime;
    
    public function __construct() {
        $this->startTime = microtime(true);
        $this->initializePatterns();
    }
    
    /**
     * Initialize malware detection patterns
     */
    private function initializePatterns() {
        // High-risk malware patterns
        $this->malwarePatterns = [
            'eval_base64' => '/eval\s*\(\s*base64_decode\s*\(/i',
            'eval_gzinflate' => '/eval\s*\(\s*gzinflate\s*\(/i',
            'eval_str_rot13' => '/eval\s*\(\s*str_rot13\s*\(/i',
            'eval_gzuncompress' => '/eval\s*\(\s*gzuncompress\s*\(/i',
            'system_exec' => '/\b(system|exec|shell_exec|passthru|proc_open|popen)\s*\(/i',
            'assert_base64' => '/assert\s*\(\s*base64_decode\s*\(/i',
            'preg_replace_eval' => '/preg_replace\s*\(.*\/e[\'\"]/i',
            'create_function' => '/create_function\s*\(/i',
            'file_put_contents_suspicious' => '/file_put_contents\s*\([^)]*base64_decode/i',
            'curl_exec_suspicious' => '/curl_exec\s*\(\s*\$[a-zA-Z_]/i',
            'obfuscated_code' => '/\$[a-zA-Z_]+\s*=\s*["\'][a-zA-Z0-9+\/=]{200,}["\']/i',
            'hidden_backdoor' => '/@include\s+["\']http/i',
            'base64_long' => '/base64_decode\s*\(["\'][a-zA-Z0-9+\/=]{500,}["\']/i',
            'suspicious_globals' => '/\$GLOBALS\s*\[\s*["\'][a-zA-Z0-9_]+["\']\s*\]\s*\(\s*\$/i',
            'variable_functions' => '/\$\{["\']GLOBALS["\']\}\s*\[/i',
            'hex_obfuscation' => '/\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}/i',
            'octal_obfuscation' => '/\\\\[0-7]{3}[a-z_]*\\\\[0-7]{3}/i',
            'octal_numbers' => '/0[0-7]{3}[+*\/-]/i',
            'string_escape_obfuscation' => '/["\'][a-z_]*\\\\(x[0-9a-f]{2}|[0-7]{3})[a-z_]*["\'].*["\'][a-z_]*\\\\(x[0-9a-f]{2}|[0-7]{3})/i',
            'getallheaders_backdoor' => '/getallheaders\s*\(\s*\)/i',
            'non_ascii_variables' => '/\$[\x80-\xff]{2,}/i',
            'cookie_backdoor' => '/\$_COOKIE\[[^\]]+\]\[[^\]]+\]\[[^\]]+\]/i',
            'obfuscated_round' => '/(round|ceil|floor)\s*\([0-9+\-*.\s\/]+\)/i',
            'hex2bin_backdoor' => '/hex2bin\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i',
            'xor_encoding' => '/chr\s*\(\s*ord\s*\([^)]+\)\s*\^\s*\d+\s*\)/i',
            'include_unlink' => '/include\s+\$[^;]+;\s*@?unlink/i',
            'extract_request' => '/extract\s*\(\s*\$_(REQUEST|POST|GET|COOKIE)\s*\)/i',
            'hex_string_keys' => '/\$_(POST|GET|REQUEST|COOKIE)\s*\[\s*["\'][^"\']*\\x[0-9a-fA-F]{2}/i',
            'hex_string_concat' => '/["\'][^"\']*\\x[0-9a-fA-F]{2}[^"\']*["\']\s*\.\s*["\'][^"\']*\\x[0-9a-fA-F]{2}/i',
            'variable_function_call' => '/\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*\$[a-zA-Z_]/i',
            'hex_encoded_functions' => '/\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*["\'](\\x[0-9a-fA-F]{2}){3,}/i',
            'stripslashes_execute' => '/stripslashes\s*\([^)]+\)\s*\)\s*&&\s*(exit|die)/i',
            'temp_file_include' => '/file_put_contents\s*\([^,]+,\s*[^)]+\).*include/is',
            'chmod_777' => '/chmod\s*\([^,]+,\s*0777\)/i',
            'malicious_redirect' => '/<\?php\s+header\s*\(\s*["\']Location:/i',
            'wp_config_injection' => '/define\s*\(\s*["\']DB_(NAME|USER|PASSWORD|HOST)["\']/i',
        ];
        
        // Suspicious patterns (lower severity)
        $this->suspiciousPatterns = [
            'base64_decode' => '/base64_decode\s*\(/i',
            'gzinflate' => '/gzinflate\s*\(/i',
            'str_rot13' => '/str_rot13\s*\(/i',
            'eval' => '/\beval\s*\(/i',
            'file_get_contents_url' => '/file_get_contents\s*\(["\']http/i',
            'wp_remote_get' => '/wp_remote_get\s*\(/i',
        ];
    }
    
    /**
     * List detected WordPress websites from cache
     */
    public function listDetectedWebsites($cacheFile) {
        if (!file_exists($cacheFile)) {
            echo "❌ Error: Cache file not found: {$cacheFile}\n";
            echo "Run detection first: php scan.php --detect --path /path/to/scan\n";
            return;
        }
        
        $cache = json_decode(file_get_contents($cacheFile), true);
        
        if (empty($cache['installations'])) {
            echo "No WordPress installations found in cache.\n";
            return;
        }
        
        $this->log("\n" . str_repeat("=", 80), 'info');
        $this->log("WordPress Installations Detected", 'success');
        $this->log(str_repeat("=", 80), 'info');
        $this->log("Cache File: {$cacheFile}", 'info');
        $this->log("Detected Date: {$cache['detected_date']}", 'info');
        $this->log("Total Installations: " . count($cache['installations']), 'success');
        $this->log(str_repeat("=", 80) . "\n", 'info');
        
        foreach ($cache['installations'] as $index => $installation) {
            $num = $index + 1;
            $this->log("[{$num}] {$installation['domain']}", 'success');
            $this->log("    Path: {$installation['path']}", 'info');
            $this->log("    WordPress: {$installation['wp_version']}", 'info');
            $this->log("    PHP: {$installation['php_version']}", 'info');
            
            // Display themes
            if (!empty($installation['themes'])) {
                $this->log("    Themes: " . count($installation['themes']), 'info');
                foreach ($installation['themes'] as $theme) {
                    $status = isset($theme['is_premium']) && $theme['is_premium'] ? '(Premium)' : '';
                    $this->log("      - {$theme['name']} v{$theme['version']} {$status}", 'info');
                }
            }
            
            // Display plugins
            if (!empty($installation['plugins'])) {
                $this->log("    Plugins: " . count($installation['plugins']), 'info');
                foreach ($installation['plugins'] as $plugin) {
                    $status = isset($plugin['is_premium']) && $plugin['is_premium'] ? '(Premium)' : '';
                    $this->log("      - {$plugin['name']} v{$plugin['version']} {$status}", 'info');
                }
            }
            
            // Display quarantined files if any
            if (!empty($installation['quarantined_files'])) {
                $this->log("    ⚠️  Quarantined Files: " . count($installation['quarantined_files']), 'warning');
                foreach ($installation['quarantined_files'] as $qFile) {
                    $this->log("      - {$qFile['file']} (" . date('Y-m-d H:i:s', $qFile['quarantined_at']) . ")", 'warning');
                }
            }
            
            $this->log("", 'info'); // Empty line between installations
        }
        
        $this->log(str_repeat("=", 80), 'info');
        $this->log("Total: " . count($cache['installations']) . " WordPress installation(s)\n", 'success');
    }
    
    /**
     * Parse command line arguments
     */
    public function parseArguments($argv) {
        $options = [
            'mode' => null,
            'path' => null,
            'report' => 'scan_report.json',
            'cached' => 'cached.json',
            'website' => null,
            'wp_version' => null,
            'plugin_name' => null,
            'theme_name' => null,
            'force' => false,
            'only_infected' => false,
            'action' => null,
            'severity' => null,
        ];
        
        for ($i = 1; $i < count($argv); $i++) {
            switch ($argv[$i]) {
                case '--dry':
                    $options['mode'] = 'scan';
                    break;
                case '--detect':
                    $options['mode'] = 'detect';
                    break;
                case '--list':
                    $options['mode'] = 'list';
                    break;
                case '--delete-high-severity':
                    $options['mode'] = 'fix';
                    $options['action'] = 'delete';
                    $options['severity'] = 'high';
                    break;
                case '--delete-medium-severity':
                    $options['mode'] = 'fix';
                    $options['action'] = 'delete';
                    $options['severity'] = 'medium';
                    break;
                case '--delete-low-severity':
                    $options['mode'] = 'fix';
                    $options['action'] = 'delete';
                    $options['severity'] = 'low';
                    break;
                case '--quarantine-high-severity':
                    $options['mode'] = 'fix';
                    $options['action'] = 'quarantine';
                    $options['severity'] = 'high';
                    break;
                case '--quarantine-medium-severity':
                    $options['mode'] = 'fix';
                    $options['action'] = 'quarantine';
                    $options['severity'] = 'medium';
                    break;
                case '--quarantine-low-severity':
                    $options['mode'] = 'fix';
                    $options['action'] = 'quarantine';
                    $options['severity'] = 'low';
                    break;
                case '--comment-high-severity':
                    $options['mode'] = 'fix';
                    $options['action'] = 'comment';
                    $options['severity'] = 'high';
                    break;
                case '--comment-medium-severity':
                    $options['mode'] = 'fix';
                    $options['action'] = 'comment';
                    $options['severity'] = 'medium';
                    break;
                case '--comment-low-severity':
                    $options['mode'] = 'fix';
                    $options['action'] = 'comment';
                    $options['severity'] = 'low';
                    break;
                case '--reinstall-core':
                    $options['mode'] = 'reinstall';
                    break;
                case '--reinstall-plugins':
                    $options['mode'] = 'reinstall-plugins';
                    break;
                case '--reinstall-plugin':
                    $options['mode'] = 'reinstall-plugin';
                    if (isset($argv[$i + 1])) {
                        $options['plugin_name'] = $argv[$i + 1];
                        $i++;
                    }
                    break;
                case '--reinstall-themes':
                    $options['mode'] = 'reinstall-themes';
                    break;
                case '--reinstall-theme':
                    $options['mode'] = 'reinstall-theme';
                    if (isset($argv[$i + 1])) {
                        $options['theme_name'] = $argv[$i + 1];
                        $i++;
                    }
                    break;
                case '--reinstall-all':
                    $options['mode'] = 'reinstall-all';
                    break;
                case '--path':
                    if (isset($argv[$i + 1])) {
                        $options['path'] = $argv[$i + 1];
                        $i++;
                    }
                    break;
                case '--report':
                    if (isset($argv[$i + 1])) {
                        $options['report'] = $argv[$i + 1];
                        $i++;
                    }
                    break;
                case '--cached':
                    if (isset($argv[$i + 1])) {
                        $options['cached'] = $argv[$i + 1];
                        $i++;
                    }
                    break;
                case '--website':
                    if (isset($argv[$i + 1])) {
                        $options['website'] = $argv[$i + 1];
                        $i++;
                    }
                    break;
                case '--wp':
                    if (isset($argv[$i + 1])) {
                        $options['wp_version'] = $argv[$i + 1];
                        $i++;
                    }
                    break;
                case '--force':
                    $options['force'] = true;
                    break;
                case '--only-infected':
                    $options['only_infected'] = true;
                    break;
                case '--no-backup':
                    $options['no_backup'] = true;
                    break;
            }
        }
        
        return $options;
    }
    
    /**
     * Apply fixes to infected files based on severity
     */
    public function applyFix($website, $action, $severity, $reportFile = 'scan_report.json', $cacheFile = 'cached.json', $noBackup = false) {
        // Validate inputs
        if (!in_array($action, ['delete', 'quarantine', 'comment'])) {
            $this->log("Error: Invalid action '$action'", 'error');
            return false;
        }
        
        if (!in_array($severity, ['high', 'medium', 'low'])) {
            $this->log("Error: Invalid severity '$severity'", 'error');
            return false;
        }
        
        // Get installation from cache
        $installation = $this->getInstallationOrFail($website, $cacheFile);
        if (!$installation) return false;
        
        $wpPath = $installation['path'];
        
        // Load report
        if (!file_exists($reportFile)) {
            $this->log("Error: Report file not found: $reportFile", 'error');
            return false;
        }
        
        $report = json_decode(file_get_contents($reportFile), true);
        if (!$report) {
            $this->log("Error: Invalid report file", 'error');
            return false;
        }
        
        // Find infected files for this installation
        $infectedFiles = [];
        foreach ($report['installations'] as $inst) {
            if ($inst['path'] === $wpPath) {
                $infectedFiles = $inst['infected_files'];
                break;
            }
        }
        
        if (empty($infectedFiles)) {
            $this->log("No infected files found for this website", 'info');
            return true;
        }
        
        // Filter by severity
        $filesToProcess = $this->filterBySeverity($infectedFiles, $severity);
        
        if (empty($filesToProcess)) {
            $this->log("No files with '$severity' severity found", 'info');
            return true;
        }
        
        $this->log("\n=== Applying Fix ===");
        $this->log("Website: {$installation['domain']}", 'info');
        $this->log("Action: $action", 'info');
        $this->log("Severity: $severity", 'info');
        $this->log("Files to process: " . count($filesToProcess), 'info');
        
        // Execute action
        switch ($action) {
            case 'delete':
                return $this->deleteFiles($filesToProcess, $wpPath, $noBackup);
            case 'quarantine':
                return $this->quarantineFiles($filesToProcess, $wpPath, $installation, $cacheFile);
            case 'comment':
                return $this->commentFiles($filesToProcess, $wpPath);
        }
        
        return false;
    }
    
    /**
     * Filter files by severity level
     */
    private function filterBySeverity($files, $severity) {
        return array_filter($files, function($file) use ($severity) {
            foreach ($file['vulnerabilities'] as $vuln) {
                if ($vuln['severity'] === $severity) {
                    return true;
                }
            }
            return false;
        });
    }
    
    /**
     * Delete infected files
     */
    private function deleteFiles($files, $wpPath, $noBackup = false) {
        $this->log("\nDeleting files...", 'info');
        
        $deleted = 0;
        $failed = 0;
        
        foreach ($files as $file) {
            $filePath = $file['file'];
            
            if (!file_exists($filePath)) {
                $this->log("  [SKIP] File not found: {$file['relative_path']}", 'warning');
                continue;
            }
            
            // Create backup if not disabled
            $canDelete = true;
            if (!$noBackup) {
                $backupPath = $filePath . '.backup.' . date('YmdHis');
                if (!copy($filePath, $backupPath)) {
                    $this->log("  [FAILED] Could not create backup: {$file['relative_path']}", 'error');
                    $failed++;
                    $canDelete = false;
                }
            }
            
            if ($canDelete) {
                if (unlink($filePath)) {
                    $this->log("  [DELETED] {$file['relative_path']}", 'success');
                    $deleted++;
                } else {
                    $this->log("  [FAILED] Could not delete: {$file['relative_path']}", 'error');
                    $failed++;
                }
            }
        }
        
        $this->log("\n=== Deletion Summary ===");
        $this->log("Deleted: $deleted files", 'success');
        $this->log("Failed: $failed files", $failed > 0 ? 'error' : 'success');
        
        return true;
    }
    
    /**
     * Quarantine infected files
     */
    private function quarantineFiles($files, $wpPath, $installation, $cacheFile) {
        $this->log("\nQuarantining files...", 'info');
        
        // Create quarantine directory
        $quarantineDir = $wpPath . '/.quarantined';
        if (!is_dir($quarantineDir)) {
            if (!mkdir($quarantineDir, 0755, true)) {
                $this->log("Error: Could not create quarantine directory", 'error');
                return false;
            }
        }
        
        $quarantined = 0;
        $failed = 0;
        $quarantinedFiles = [];
        
        foreach ($files as $file) {
            $filePath = $file['file'];
            
            if (!file_exists($filePath)) {
                $this->log("  [SKIP] File not found: {$file['relative_path']}", 'warning');
                continue;
            }
            
            // Generate quarantine file name
            $relativePath = str_replace($wpPath . '/', '', $filePath);
            $quarantineName = str_replace('/', '_', $relativePath) . '.quarantined';
            $quarantinePath = $quarantineDir . '/' . $quarantineName;
            
            // Move file to quarantine
            if (rename($filePath, $quarantinePath)) {
                $this->log("  [QUARANTINED] {$file['relative_path']}", 'success');
                $quarantined++;
                
                $quarantinedFiles[] = [
                    'original_path' => $filePath,
                    'quarantine_path' => $quarantinePath,
                    'relative_path' => $file['relative_path'],
                    'quarantined_date' => date('Y-m-d H:i:s'),
                    'vulnerabilities' => $file['vulnerabilities'],
                ];
            } else {
                $this->log("  [FAILED] Could not quarantine: {$file['relative_path']}", 'error');
                $failed++;
            }
        }
        
        // Update cache with quarantined files
        if (!empty($quarantinedFiles)) {
            $this->updateCacheWithQuarantinedFiles($installation, $quarantinedFiles, $cacheFile);
        }
        
        $this->log("\n=== Quarantine Summary ===");
        $this->log("Quarantined: $quarantined files", 'success');
        $this->log("Failed: $failed files", $failed > 0 ? 'error' : 'success');
        $this->log("Quarantine directory: $quarantineDir", 'info');
        
        return true;
    }
    
    /**
     * Comment out infected code
     */
    private function commentFiles($files, $wpPath) {
        $this->log("\nCommenting out malicious code...", 'info');
        
        $commented = 0;
        $failed = 0;
        
        foreach ($files as $file) {
            $filePath = $file['file'];
            
            if (!file_exists($filePath)) {
                $this->log("  [SKIP] File not found: {$file['relative_path']}", 'warning');
                continue;
            }
            
            $content = file_get_contents($filePath);
            if ($content === false) {
                $this->log("  [FAILED] Could not read: {$file['relative_path']}", 'error');
                $failed++;
                continue;
            }
            
            // Create backup
            $backupPath = $filePath . '.backup.' . date('YmdHis');
            if (!copy($filePath, $backupPath)) {
                $this->log("  [FAILED] Could not create backup: {$file['relative_path']}", 'error');
                $failed++;
                continue;
            }
            
            // Add warning comment at the top
            $warning = "<?php\n";
            $warning .= "/* ============================================\n";
            $warning .= " * WARNING: This file has been flagged as potentially infected\n";
            $warning .= " * Date: " . date('Y-m-d H:i:s') . "\n";
            $warning .= " * Vulnerabilities found:\n";
            foreach ($file['vulnerabilities'] as $vuln) {
                $warning .= " *   - {$vuln['pattern']} ({$vuln['severity']} severity)\n";
            }
            $warning .= " * Original content has been preserved below but should be reviewed\n";
            $warning .= " * ============================================ */\n";
            $warning .= "die('This file has been disabled due to security concerns. Contact administrator.');\n";
            $warning .= "/* ORIGINAL CONTENT BELOW - DO NOT EXECUTE\n";
            
            // Remove opening PHP tag from original content if present
            $content = preg_replace('/^\s*<\?php\s*/i', '', $content);
            
            $newContent = $warning . $content . "\n*/\n";
            
            if (file_put_contents($filePath, $newContent)) {
                $this->log("  [COMMENTED] {$file['relative_path']}", 'success');
                $commented++;
            } else {
                $this->log("  [FAILED] Could not write: {$file['relative_path']}", 'error');
                $failed++;
            }
        }
        
        $this->log("\n=== Comment Summary ===");
        $this->log("Commented: $commented files", 'success');
        $this->log("Failed: $failed files", $failed > 0 ? 'error' : 'success');
        $this->log("\nNote: Commented files are disabled and safe but should be reviewed.", 'warning');
        
        return true;
    }
    
    /**
     * Update cache with quarantined files information
     */
    private function updateCacheWithQuarantinedFiles($installation, $quarantinedFiles, $cacheFile) {
        $cache = $this->loadCache($cacheFile);
        if (!$cache) return;
        
        // Find and update the installation
        foreach ($cache['installations'] as &$inst) {
            if ($inst['path'] === $installation['path']) {
                if (!isset($inst['quarantined_files'])) {
                    $inst['quarantined_files'] = [];
                }
                
                // Add new quarantined files
                $inst['quarantined_files'] = array_merge(
                    $inst['quarantined_files'],
                    $quarantinedFiles
                );
                
                break;
            }
        }
        
        // Save updated cache
        $json = json_encode($cache, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        file_put_contents($cacheFile, $json);
        
        $this->log("Cache updated with quarantined files", 'info');
    }
    
    /**
     * Check if plugin is available on WordPress.org
     */
    private function isPluginAvailableOnWordPress($slug) {
        $url = "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&slug=" . urlencode($slug);
        
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode === 200 && $response) {
            $data = json_decode($response, true);
            return $data !== null ? $data : false;
        }
        
        return false;
    }
    
    /**
     * Check if theme is available on WordPress.org
     */
    private function isThemeAvailableOnWordPress($slug) {
        $url = "https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]=" . urlencode($slug);
        
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode === 200 && $response) {
            $data = json_decode($response, true);
            return $data !== null ? $data : false;
        }
        
        return false;
    }
    
    /**
     * Reinstall plugins for a WordPress installation
     */
    public function reinstallPlugins($website, $cacheFile = 'cached.json', $specificPlugin = null, $force = false, $onlyInfected = false, $reportFile = null, $noBackup = false) {
        $installation = $this->getInstallationOrFail($website, $cacheFile);
        if (!$installation) return false;
        
        $wpPath = $installation['path'];
        $plugins = $installation['plugins'];
        
        // Filter by specific plugin if provided
        if ($specificPlugin) {
            $plugins = array_filter($plugins, function($p) use ($specificPlugin) {
                return $p['name'] === $specificPlugin;
            });
            
            if (empty($plugins)) {
                $this->log("Error: Plugin '$specificPlugin' not found in cache", 'error');
                return false;
            }
        }
        
        // Filter by infected files if requested
        if ($onlyInfected && $reportFile) {
            $plugins = $this->filterInfectedPlugins($plugins, $wpPath, $reportFile);
        }
        
        $this->log("\n=== Plugin Reinstallation ===");
        $this->log("Website: {$installation['domain']}", 'info');
        $this->log("Total plugins to process: " . count($plugins), 'info');
        
        $stats = ['reinstalled' => 0, 'skipped_premium' => 0, 'failed' => 0, 'skipped_version' => 0];
        
        foreach ($plugins as $plugin) {
            $this->log("\n[{$plugin['name']}] Processing...", 'info');
            
            // Check if available on WordPress.org
            $pluginInfo = $this->isPluginAvailableOnWordPress($plugin['name']);
            
            if (!$pluginInfo) {
                $this->log("  ⚠️  SKIPPED - Premium/Not available on WordPress.org", 'warning');
                $stats['skipped_premium']++;
                continue;
            }
            
            $latestVersion = $pluginInfo['version'];
            $currentVersion = $plugin['version'];
            
            // Skip if versions match and not forcing
            if (!$force && $currentVersion === $latestVersion) {
                $this->log("  ℹ️  SKIPPED - Already at latest version ($currentVersion)", 'info');
                $stats['skipped_version']++;
                continue;
            }
            
            $this->log("  Current: $currentVersion | Latest: $latestVersion", 'info');
            
            // Download and reinstall
            $downloadUrl = $pluginInfo['download_link'];
            $zipFile = "/tmp/{$plugin['name']}-{$latestVersion}.zip";
            
            $this->log("  Downloading...", 'info');
            
            if (!$this->downloadFile($downloadUrl, $zipFile)) {
                $this->log("  ❌ FAILED - Could not download", 'error');
                $stats['failed']++;
                continue;
            }
            
            // Backup current plugin
            $backupPath = null;
            
            if (!$noBackup && is_dir($plugin['path'])) {
                $backupPath = $plugin['path'] . '.backup-' . date('YmdHis');
                $this->log("  Creating backup...", 'info');
                rename($plugin['path'], $backupPath);
            } elseif ($noBackup && is_dir($plugin['path'])) {
                $this->recursiveDelete($plugin['path']);
            }
            
            // Extract
            $this->log("  Extracting...", 'info');
            $extractDir = "/tmp/plugin-extract-" . time();
            
            if (!$this->extractZip($zipFile, $extractDir)) {
                $this->log("  ❌ FAILED - Could not extract", 'error');
                
                // Restore backup
                if (file_exists($backupPath)) {
                    rename($backupPath, $plugin['path']);
                }
                
                unlink($zipFile);
                $stats['failed']++;
                continue;
            }
            
            // Move to plugins directory
            $extractedPlugin = "$extractDir/{$plugin['name']}";
            $targetPath = $plugin['path'];
            
            if (is_dir($extractedPlugin)) {
                rename($extractedPlugin, $targetPath);
                $this->log("  ✅ REINSTALLED - Version $latestVersion", 'success');
                $stats['reinstalled']++;
            } else {
                $this->log("  ❌ FAILED - Extracted structure invalid", 'error');
                
                // Restore backup
                if (file_exists($backupPath)) {
                    rename($backupPath, $plugin['path']);
                }
                
                $stats['failed']++;
            }
            
            // Cleanup
            unlink($zipFile);
            $this->recursiveDelete($extractDir);
        }
        
        $this->log("\n=== Reinstallation Summary ===", 'success');
        $this->log("✅ Reinstalled: {$stats['reinstalled']}", 'success');
        $this->log("⚠️  Skipped (Premium): {$stats['skipped_premium']}", 'warning');
        $this->log("ℹ️  Skipped (Up-to-date): {$stats['skipped_version']}", 'info');
        $this->log("❌ Failed: {$stats['failed']}", $stats['failed'] > 0 ? 'error' : 'info');
        
        return true;
    }
    
    /**
     * Reinstall themes for a WordPress installation
     */
    public function reinstallThemes($website, $cacheFile = 'cached.json', $specificTheme = null, $force = false, $onlyInfected = false, $reportFile = null, $noBackup = false) {
        $installation = $this->getInstallationOrFail($website, $cacheFile);
        if (!$installation) return false;
        
        $wpPath = $installation['path'];
        $themes = $installation['themes'];
        
        // Filter by specific theme if provided
        if ($specificTheme) {
            $themes = array_filter($themes, function($t) use ($specificTheme) {
                return $t['name'] === $specificTheme;
            });
            
            if (empty($themes)) {
                $this->log("Error: Theme '$specificTheme' not found in cache", 'error');
                return false;
            }
        }
        
        // Filter by infected files if requested
        if ($onlyInfected && $reportFile) {
            $themes = $this->filterInfectedThemes($themes, $wpPath, $reportFile);
        }
        
        $this->log("\n=== Theme Reinstallation ===");
        $this->log("Website: {$installation['domain']}", 'info');
        $this->log("Total themes to process: " . count($themes), 'info');
        
        $stats = ['reinstalled' => 0, 'skipped_premium' => 0, 'failed' => 0, 'skipped_version' => 0];
        
        foreach ($themes as $theme) {
            $this->log("\n[{$theme['name']}] Processing...", 'info');
            
            // Check if available on WordPress.org
            $themeInfo = $this->isThemeAvailableOnWordPress($theme['name']);
            
            if (!$themeInfo) {
                $this->log("  ⚠️  SKIPPED - Premium/Not available on WordPress.org", 'warning');
                $stats['skipped_premium']++;
                continue;
            }
            
            $latestVersion = $themeInfo['version'];
            $currentVersion = $theme['version'];
            
            // Skip if versions match and not forcing
            if (!$force && $currentVersion === $latestVersion) {
                $this->log("  ℹ️  SKIPPED - Already at latest version ($currentVersion)", 'info');
                $stats['skipped_version']++;
                continue;
            }
            
            $this->log("  Current: $currentVersion | Latest: $latestVersion", 'info');
            
            // Download and reinstall
            $downloadUrl = "https://downloads.wordpress.org/theme/{$theme['name']}.{$latestVersion}.zip";
            $zipFile = "/tmp/{$theme['name']}-{$latestVersion}.zip";
            
            $this->log("  Downloading...", 'info');
            
            if (!$this->downloadFile($downloadUrl, $zipFile)) {
                $this->log("  ❌ FAILED - Could not download", 'error');
                $stats['failed']++;
                continue;
            }
            
            // Backup current theme
            $backupPath = null;
            
            if (!$noBackup && is_dir($theme['path'])) {
                $backupPath = $theme['path'] . '.backup-' . date('YmdHis');
                $this->log("  Creating backup...", 'info');
                rename($theme['path'], $backupPath);
            } elseif ($noBackup && is_dir($theme['path'])) {
                $this->recursiveDelete($theme['path']);
            }
            
            // Extract
            $this->log("  Extracting...", 'info');
            $extractDir = "/tmp/theme-extract-" . time();
            
            if (!$this->extractZip($zipFile, $extractDir)) {
                $this->log("  ❌ FAILED - Could not extract", 'error');
                
                // Restore backup
                if (file_exists($backupPath)) {
                    rename($backupPath, $theme['path']);
                }
                
                unlink($zipFile);
                $stats['failed']++;
                continue;
            }
            
            // Move to themes directory
            $extractedTheme = "$extractDir/{$theme['name']}";
            $targetPath = $theme['path'];
            
            if (is_dir($extractedTheme)) {
                rename($extractedTheme, $targetPath);
                $this->log("  ✅ REINSTALLED - Version $latestVersion", 'success');
                $stats['reinstalled']++;
            } else {
                $this->log("  ❌ FAILED - Extracted structure invalid", 'error');
                
                // Restore backup
                if (file_exists($backupPath)) {
                    rename($backupPath, $theme['path']);
                }
                
                $stats['failed']++;
            }
            
            // Cleanup
            unlink($zipFile);
            $this->recursiveDelete($extractDir);
        }
        
        $this->log("\n=== Reinstallation Summary ===", 'success');
        $this->log("✅ Reinstalled: {$stats['reinstalled']}", 'success');
        $this->log("⚠️  Skipped (Premium): {$stats['skipped_premium']}", 'warning');
        $this->log("ℹ️  Skipped (Up-to-date): {$stats['skipped_version']}", 'info');
        $this->log("❌ Failed: {$stats['failed']}", $stats['failed'] > 0 ? 'error' : 'info');
        
        return true;
    }
    
    /**
     * Reinstall everything (core + plugins + themes)
     */
    public function reinstallAll($website, $cacheFile = 'cached.json', $wpVersion = null, $force = false, $noBackup = false) {
        $this->log("\n=== Complete WordPress Reinstallation ===", 'success');
        
        // Reinstall core
        $this->log("\n--- Step 1: Reinstalling WordPress Core ---", 'info');
        if (!$this->reinstallWordPressCore($website, $cacheFile, $wpVersion, $noBackup)) {
            $this->log("Core reinstallation failed. Aborting.", 'error');
            return false;
        }
        
        // Reinstall plugins
        $this->log("\n--- Step 2: Reinstalling Plugins ---", 'info');
        $this->reinstallPlugins($website, $cacheFile, null, $force, false, null, $noBackup);
        
        // Reinstall themes
        $this->log("\n--- Step 3: Reinstalling Themes ---", 'info');
        $this->reinstallThemes($website, $cacheFile, null, $force, false, null, $noBackup);
        
        $this->log("\n=== Complete Reinstallation Finished ===", 'success');
        $this->log("Please test your website thoroughly.", 'warning');
        
        return true;
    }
    
    /**
     * Helper to get installation or fail with error
     */
    private function getInstallationOrFail($website, $cacheFile) {
        if (!file_exists($cacheFile)) {
            $this->log("Error: Cache file not found: $cacheFile", 'error');
            $this->log("Please run detection first: php scan.php --detect --path /your/path", 'warning');
            return null;
        }
        
        $installation = $this->findInstallationByWebsite($website, $cacheFile);
        
        if (!$installation) {
            $this->log("Error: WordPress installation not found for: $website", 'error');
            $this->log("Available installations:", 'info');
            
            $cache = $this->loadCache($cacheFile);
            foreach ($cache['installations'] as $inst) {
                $this->log("  - {$inst['domain']} ({$inst['path']})", 'info');
            }
            
            return null;
        }
        
        return $installation;
    }
    
    /**
     * Filter plugins that have infected files
     */
    private function filterInfectedPlugins($plugins, $wpPath, $reportFile) {
        if (!file_exists($reportFile)) {
            return $plugins;
        }
        
        $report = json_decode(file_get_contents($reportFile), true);
        if (!$report) return $plugins;
        
        $infectedPaths = [];
        
        foreach ($report['installations'] as $installation) {
            if ($installation['path'] === $wpPath) {
                foreach ($installation['infected_files'] as $file) {
                    $infectedPaths[] = $file['file'];
                }
                break;
            }
        }
        
        return array_filter($plugins, function($plugin) use ($infectedPaths) {
            foreach ($infectedPaths as $path) {
                if (strpos($path, $plugin['path']) === 0) {
                    return true;
                }
            }
            return false;
        });
    }
    
    /**
     * Filter themes that have infected files
     */
    private function filterInfectedThemes($themes, $wpPath, $reportFile) {
        if (!file_exists($reportFile)) {
            return $themes;
        }
        
        $report = json_decode(file_get_contents($reportFile), true);
        if (!$report) return $themes;
        
        $infectedPaths = [];
        
        foreach ($report['installations'] as $installation) {
            if ($installation['path'] === $wpPath) {
                foreach ($installation['infected_files'] as $file) {
                    $infectedPaths[] = $file['file'];
                }
                break;
            }
        }
        
        return array_filter($themes, function($theme) use ($infectedPaths) {
            foreach ($infectedPaths as $path) {
                if (strpos($path, $theme['path']) === 0) {
                    return true;
                }
            }
            return false;
        });
    }
    
    /**
     * Detect WordPress installations and cache information
     */
    public function detectAndCacheInstallations($rootPath, $cacheFile = 'cached.json') {
        $installations = $this->findWordPressInstallations($rootPath);
        $cachedData = [];
        
        foreach ($installations as $wpPath) {
            $this->log("\nDetecting WordPress details: $wpPath");
            
            $info = [
                'path' => $wpPath,
                'domain' => $this->extractDomain($wpPath),
                'php_version' => PHP_VERSION,
                'wp_version' => $this->getWordPressVersion($wpPath),
                'detected_date' => date('Y-m-d H:i:s'),
                'themes' => $this->getThemes($wpPath),
                'plugins' => $this->getPlugins($wpPath),
            ];
            
            $cachedData[] = $info;
            
            $this->log("  Domain: {$info['domain']}", 'success');
            $this->log("  WordPress: {$info['wp_version']}", 'success');
            $this->log("  Themes: " . count($info['themes']), 'success');
            $this->log("  Plugins: " . count($info['plugins']), 'success');
        }
        
        // Save to cache file
        $json = json_encode(['detected_date' => date('Y-m-d H:i:s'), 'installations' => $cachedData], 
                           JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        
        if (file_put_contents($cacheFile, $json)) {
            $this->log("\nCache saved to: $cacheFile", 'success');
            $this->log("Total installations cached: " . count($cachedData), 'success');
            return true;
        } else {
            $this->log("\nError: Could not save cache to: $cacheFile", 'error');
            return false;
        }
    }
    
    /**
     * Extract domain from path
     */
    private function extractDomain($path) {
        // Try to extract domain from path (e.g., /var/www/example.com/public)
        $parts = explode('/', trim($path, '/'));
        
        // Look for domain-like patterns
        foreach ($parts as $part) {
            if (preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/', $part)) {
                return $part;
            }
        }
        
        // If no domain found, return the last directory name
        return end($parts);
    }
    
    /**
     * Get WordPress version from installation
     */
    private function getWordPressVersion($wpPath) {
        $versionFile = "$wpPath/wp-includes/version.php";
        
        if (!file_exists($versionFile)) {
            return 'Unknown';
        }
        
        $content = file_get_contents($versionFile);
        
        if (preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]/', $content, $matches)) {
            return $matches[1];
        }
        
        return 'Unknown';
    }
    
    /**
     * Get installed themes
     */
    private function getThemes($wpPath) {
        $themesDir = "$wpPath/wp-content/themes";
        $themes = [];
        
        if (!is_dir($themesDir)) {
            return $themes;
        }
        
        $dirs = scandir($themesDir);
        
        foreach ($dirs as $dir) {
            if ($dir === '.' || $dir === '..') continue;
            
            $themeDir = "$themesDir/$dir";
            
            if (is_dir($themeDir)) {
                $styleFile = "$themeDir/style.css";
                
                if (file_exists($styleFile)) {
                    $themeInfo = $this->parseThemeInfo($styleFile);
                    $themes[] = [
                        'name' => $dir,
                        'title' => $themeInfo['name'] ?? $dir,
                        'version' => $themeInfo['version'] ?? 'Unknown',
                        'path' => $themeDir,
                    ];
                }
            }
        }
        
        return $themes;
    }
    
    /**
     * Parse theme information from style.css
     */
    private function parseThemeInfo($styleFile) {
        $content = file_get_contents($styleFile, false, null, 0, 8192);
        $info = [];
        
        if (preg_match('/Theme Name:\s*(.+)/i', $content, $matches)) {
            $info['name'] = trim($matches[1]);
        }
        
        if (preg_match('/Version:\s*(.+)/i', $content, $matches)) {
            $info['version'] = trim($matches[1]);
        }
        
        return $info;
    }
    
    /**
     * Get installed plugins
     */
    private function getPlugins($wpPath) {
        $pluginsDir = "$wpPath/wp-content/plugins";
        $plugins = [];
        
        if (!is_dir($pluginsDir)) {
            return $plugins;
        }
        
        $dirs = scandir($pluginsDir);
        
        foreach ($dirs as $dir) {
            if ($dir === '.' || $dir === '..') continue;
            
            $pluginDir = "$pluginsDir/$dir";
            
            if (is_dir($pluginDir)) {
                // Look for main plugin file
                $files = glob("$pluginDir/*.php");
                
                foreach ($files as $file) {
                    $pluginInfo = $this->parsePluginInfo($file);
                    
                    if (!empty($pluginInfo['name'])) {
                        $plugins[] = [
                            'name' => $dir,
                            'title' => $pluginInfo['name'],
                            'version' => $pluginInfo['version'] ?? 'Unknown',
                            'path' => $pluginDir,
                        ];
                        break;
                    }
                }
            } elseif (pathinfo($dir, PATHINFO_EXTENSION) === 'php') {
                // Single file plugin
                $file = "$pluginsDir/$dir";
                $pluginInfo = $this->parsePluginInfo($file);
                
                if (!empty($pluginInfo['name'])) {
                    $plugins[] = [
                        'name' => pathinfo($dir, PATHINFO_FILENAME),
                        'title' => $pluginInfo['name'],
                        'version' => $pluginInfo['version'] ?? 'Unknown',
                        'path' => $file,
                    ];
                }
            }
        }
        
        return $plugins;
    }
    
    /**
     * Parse plugin information from plugin file header
     */
    private function parsePluginInfo($pluginFile) {
        $content = @file_get_contents($pluginFile, false, null, 0, 8192);
        
        if ($content === false) {
            return [];
        }
        
        $info = [];
        
        if (preg_match('/Plugin Name:\s*(.+)/i', $content, $matches)) {
            $info['name'] = trim($matches[1]);
        }
        
        if (preg_match('/Version:\s*(.+)/i', $content, $matches)) {
            $info['version'] = trim($matches[1]);
        }
        
        return $info;
    }
    
    /**
     * Load cached installations
     */
    private function loadCache($cacheFile) {
        if (!file_exists($cacheFile)) {
            return null;
        }
        
        $content = file_get_contents($cacheFile);
        $data = json_decode($content, true);
        
        if (!$data || !isset($data['installations'])) {
            return null;
        }
        
        return $data;
    }
    
    /**
     * Find WordPress installation by website name
     */
    private function findInstallationByWebsite($website, $cacheFile) {
        $cache = $this->loadCache($cacheFile);
        
        if (!$cache) {
            return null;
        }
        
        foreach ($cache['installations'] as $installation) {
            if ($installation['domain'] === $website || 
                strpos($installation['path'], $website) !== false) {
                return $installation;
            }
        }
        
        return null;
    }
    
    /**
     * Reinstall WordPress core files
     */
    public function reinstallWordPressCore($website, $cacheFile = 'cached.json', $wpVersion = null, $noBackup = false) {
        // Check if cache exists
        if (!file_exists($cacheFile)) {
            $this->log("Error: Cache file not found: $cacheFile", 'error');
            $this->log("Please run detection first: php scan.php --detect --path /your/path", 'warning');
            return false;
        }
        
        // Find installation
        $installation = $this->findInstallationByWebsite($website, $cacheFile);
        
        if (!$installation) {
            $this->log("Error: WordPress installation not found for: $website", 'error');
            $this->log("Available installations:", 'info');
            
            $cache = $this->loadCache($cacheFile);
            foreach ($cache['installations'] as $inst) {
                $this->log("  - {$inst['domain']} ({$inst['path']})", 'info');
            }
            
            return false;
        }
        
        $wpPath = $installation['path'];
        $currentVersion = $installation['wp_version'];
        $targetVersion = $wpVersion ?? $currentVersion;
        
        $this->log("\n=== WordPress Core Reinstallation ===");
        $this->log("Website: {$installation['domain']}", 'info');
        $this->log("Path: $wpPath", 'info');
        $this->log("Current Version: $currentVersion", 'info');
        $this->log("Target Version: $targetVersion", 'info');
        
        // Create backup directory
        $backupDir = null;
        
        if (!$noBackup) {
            $backupDir = $wpPath . '/wp-backup-' . date('YmdHis');
            
            $this->log("\nCreating backup...", 'info');
            
            if (!mkdir($backupDir, 0755, true)) {
                $this->log("Error: Could not create backup directory", 'error');
                return false;
            }
            
            // Backup critical files
            $filesToBackup = ['wp-config.php', '.htaccess', 'wp-content'];
            
            foreach ($filesToBackup as $file) {
                $source = "$wpPath/$file";
                $dest = "$backupDir/$file";
                
                if (file_exists($source)) {
                    if (is_dir($source)) {
                        $this->log("  Backing up directory: $file", 'info');
                        $this->recursiveCopy($source, $dest);
                    } else {
                        $this->log("  Backing up file: $file", 'info');
                        copy($source, $dest);
                    }
                }
            }
            
            $this->log("Backup created: $backupDir", 'success');
        } else {
            $this->log("\nSkipping backup (--no-backup enabled)", 'warning');
        }
        
        // Download WordPress
        $this->log("\nDownloading WordPress $targetVersion...", 'info');
        
        $downloadUrl = "https://wordpress.org/wordpress-$targetVersion.zip";
        $zipFile = "/tmp/wordpress-$targetVersion.zip";
        
        if (!$this->downloadFile($downloadUrl, $zipFile)) {
            $this->log("Error: Could not download WordPress", 'error');
            return false;
        }
        
        $this->log("Downloaded successfully", 'success');
        
        // Extract WordPress
        $this->log("\nExtracting WordPress...", 'info');
        
        $extractDir = "/tmp/wordpress-extract-" . time();
        
        if (!$this->extractZip($zipFile, $extractDir)) {
            $this->log("Error: Could not extract WordPress", 'error');
            unlink($zipFile);
            return false;
        }
        
        $this->log("Extracted successfully", 'success');
        
        // Replace core files
        $this->log("\nReplacing core files...", 'info');
        
        $wpSource = "$extractDir/wordpress";
        
        // Directories to replace
        $dirsToReplace = ['wp-admin', 'wp-includes'];
        
        foreach ($dirsToReplace as $dir) {
            $source = "$wpSource/$dir";
            $dest = "$wpPath/$dir";
            
            if (is_dir($dest)) {
                $this->log("  Removing old $dir...", 'info');
                $this->recursiveDelete($dest);
            }
            
            $this->log("  Installing new $dir...", 'info');
            $this->recursiveCopy($source, $dest);
        }
        
        // Replace root PHP files
        $rootFiles = glob("$wpSource/*.php");
        
        foreach ($rootFiles as $file) {
            $filename = basename($file);
            
            // Skip wp-config.php
            if ($filename === 'wp-config.php' || $filename === 'wp-config-sample.php') {
                continue;
            }
            
            $dest = "$wpPath/$filename";
            $this->log("  Replacing $filename", 'info');
            copy($file, $dest);
        }
        
        // Copy other root files
        $otherFiles = ['license.txt', 'readme.html'];
        
        foreach ($otherFiles as $filename) {
            $source = "$wpSource/$filename";
            $dest = "$wpPath/$filename";
            
            if (file_exists($source)) {
                copy($source, $dest);
            }
        }
        
        // Cleanup
        $this->log("\nCleaning up...", 'info');
        unlink($zipFile);
        $this->recursiveDelete($extractDir);
        
        $this->log("\n=== Reinstallation Complete ===", 'success');
        $this->log("WordPress core has been reinstalled", 'success');
        $this->log("Backup location: $backupDir", 'success');
        $this->log("\nIMPORTANT: Please test your website and verify everything works correctly.", 'warning');
        
        return true;
    }
    
    /**
     * Download file from URL
     */
    private function downloadFile($url, $destination) {
        $ch = curl_init($url);
        $fp = fopen($destination, 'wb');
        
        curl_setopt($ch, CURLOPT_FILE, $fp);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 300);
        
        $result = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        curl_close($ch);
        fclose($fp);
        
        if ($result === false || $httpCode !== 200) {
            unlink($destination);
            return false;
        }
        
        return true;
    }
    
    /**
     * Extract ZIP file
     */
    private function extractZip($zipFile, $destination) {
        if (!class_exists('ZipArchive')) {
            $this->log("Error: ZipArchive extension not available", 'error');
            return false;
        }
        
        $zip = new ZipArchive();
        
        if ($zip->open($zipFile) !== true) {
            return false;
        }
        
        if (!is_dir($destination)) {
            mkdir($destination, 0755, true);
        }
        
        $result = $zip->extractTo($destination);
        $zip->close();
        
        return $result;
    }
    
    /**
     * Recursive copy
     */
    private function recursiveCopy($source, $dest) {
        if (!is_dir($dest)) {
            mkdir($dest, 0755, true);
        }
        
        $dir = opendir($source);
        
        while (($file = readdir($dir)) !== false) {
            if ($file === '.' || $file === '..') {
                continue;
            }
            
            $srcFile = "$source/$file";
            $destFile = "$dest/$file";
            
            if (is_dir($srcFile)) {
                $this->recursiveCopy($srcFile, $destFile);
            } else {
                copy($srcFile, $destFile);
            }
        }
        
        closedir($dir);
    }
    
    /**
     * Recursive delete
     */
    private function recursiveDelete($dir) {
        if (!is_dir($dir)) {
            return;
        }
        
        $files = array_diff(scandir($dir), ['.', '..']);
        
        foreach ($files as $file) {
            $path = "$dir/$file";
            
            if (is_dir($path)) {
                $this->recursiveDelete($path);
            } else {
                unlink($path);
            }
        }
        
        rmdir($dir);
    }
    
    /**
     * Find WordPress installations in a directory
     */
    public function findWordPressInstallations($rootPath) {
        $installations = [];
        
        if (!is_dir($rootPath)) {
            $this->log("Error: Path does not exist: $rootPath", 'error');
            return $installations;
        }
        
        $this->log("Searching for WordPress installations in: $rootPath");
        
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($rootPath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        
        $checkedPaths = [];
        
        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getFilename() === 'wp-config.php') {
                $wpPath = dirname($file->getPathname());
                
                // Verify it's a valid WordPress installation
                if ($this->isValidWordPressInstallation($wpPath) && !in_array($wpPath, $checkedPaths)) {
                    $installations[] = $wpPath;
                    $checkedPaths[] = $wpPath;
                    $this->log("Found WordPress installation: $wpPath", 'success');
                }
            }
        }
        
        $this->log("Total WordPress installations found: " . count($installations), 'success');
        return $installations;
    }
    
    /**
     * Verify if a path contains a valid WordPress installation
     */
    private function isValidWordPressInstallation($path) {
        $requiredFiles = ['wp-config.php', 'wp-load.php', 'wp-settings.php'];
        $requiredDirs = ['wp-includes', 'wp-content', 'wp-admin'];
        
        foreach ($requiredFiles as $file) {
            if (!file_exists("$path/$file")) {
                return false;
            }
        }
        
        foreach ($requiredDirs as $dir) {
            if (!is_dir("$path/$dir")) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Scan a WordPress installation for infected files
     */
    public function scanWordPressInstallation($wpPath) {
        $this->log("\nScanning WordPress installation: $wpPath");
        
        $siteReport = [
            'path' => $wpPath,
            'scan_date' => date('Y-m-d H:i:s'),
            'infected_files' => [],
            'total_scanned' => 0,
            'total_infected' => 0,
        ];
        
        // Directories to scan
        $scanDirs = [
            "$wpPath/wp-content/themes",
            "$wpPath/wp-content/plugins",
            "$wpPath/wp-content/uploads",
            "$wpPath/wp-includes",
        ];
        
        // Also scan root PHP files
        $rootFiles = glob("$wpPath/*.php");
        
        foreach ($rootFiles as $file) {
            if (is_file($file)) {
                $result = $this->scanFile($file, $wpPath);
                if ($result) {
                    $siteReport['infected_files'][] = $result;
                    $siteReport['total_infected']++;
                    $this->infectedFiles++;
                }
                $siteReport['total_scanned']++;
                $this->scannedFiles++;
            }
        }
        
        // Scan each directory
        foreach ($scanDirs as $dir) {
            if (is_dir($dir)) {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
                );
                
                foreach ($iterator as $file) {
                    if ($file->isFile()) {
                        $ext = strtolower($file->getExtension());
                        
                        // Scan PHP files and images
                        if (in_array($ext, ['php', 'php3', 'php4', 'php5', 'phtml', 'suspected'])) {
                            $result = $this->scanFile($file->getPathname(), $wpPath);
                            if ($result) {
                                $siteReport['infected_files'][] = $result;
                                $siteReport['total_infected']++;
                                $this->infectedFiles++;
                            }
                            $siteReport['total_scanned']++;
                            $this->scannedFiles++;
                        } elseif (in_array($ext, ['jpg', 'jpeg', 'png', 'gif', 'ico'])) {
                            $result = $this->scanImageFile($file->getPathname(), $wpPath);
                            if ($result) {
                                $siteReport['infected_files'][] = $result;
                                $siteReport['total_infected']++;
                                $this->infectedFiles++;
                            }
                            $siteReport['total_scanned']++;
                            $this->scannedFiles++;
                        }
                    }
                }
            }
        }
        
        $this->log("Scanned {$siteReport['total_scanned']} files, found {$siteReport['total_infected']} infected files", 
                   $siteReport['total_infected'] > 0 ? 'warning' : 'success');
        
        return $siteReport;
    }
    
    /**
     * Scan a single PHP file for malware
     */
    private function scanFile($filePath, $wpPath) {
        $content = @file_get_contents($filePath);
        
        if ($content === false) {
            return null;
        }
        
        $vulnerabilities = [];
        $fileName = basename($filePath);
        
        // Check malware patterns
        foreach ($this->malwarePatterns as $name => $pattern) {
            // Skip wp_config_injection check for legitimate WordPress config files
            if ($name === 'wp_config_injection' && 
                ($fileName === 'wp-config.php' || $fileName === 'wp-config-sample.php')) {
                continue;
            }
            
            $result = @preg_match($pattern, $content);
            if ($result === false) {
                echo "⚠️  Regex error in pattern '$name': $pattern\n";
                echo "    Error: " . preg_last_error_msg() . "\n";
                continue;
            }
            
            if ($result) {
                $vulnerabilities[] = [
                    'type' => 'malware',
                    'pattern' => $name,
                    'severity' => 'high',
                ];
            }
        }
        
        // Check suspicious patterns
        foreach ($this->suspiciousPatterns as $name => $pattern) {
            $result = @preg_match($pattern, $content);
            if ($result === false) {
                echo "⚠️  Regex error in suspicious pattern '$name': $pattern\n";
                echo "    Error: " . preg_last_error_msg() . "\n";
                continue;
            }
            
            if ($result) {
                $vulnerabilities[] = [
                    'type' => 'suspicious',
                    'pattern' => $name,
                    'severity' => 'medium',
                ];
            }
        }
        
        // Additional checks
        $fileSize = filesize($filePath);
        $permissions = substr(sprintf('%o', fileperms($filePath)), -4);
        
        // Check for suspicious file characteristics
        if ($permissions === '0777') {
            $vulnerabilities[] = [
                'type' => 'permissions',
                'pattern' => 'file_permissions_777',
                'severity' => 'medium',
            ];
        }
        
        if (!empty($vulnerabilities)) {
            $relativePath = str_replace($wpPath . '/', '', $filePath);
            
            $this->log("  [INFECTED] $relativePath", 'error');
            foreach ($vulnerabilities as $vuln) {
                $this->log("    - {$vuln['pattern']} ({$vuln['severity']} severity)", 'warning');
            }
            
            return [
                'file' => $filePath,
                'relative_path' => $relativePath,
                'vulnerabilities' => $vulnerabilities,
                'file_size' => $fileSize,
                'permissions' => $permissions,
                'modified_date' => date('Y-m-d H:i:s', filemtime($filePath)),
            ];
        }
        
        return null;
    }
    
    /**
     * Scan image files for embedded PHP code
     */
    private function scanImageFile($filePath, $wpPath) {
        $content = @file_get_contents($filePath, false, null, 0, 8192); // Read first 8KB
        
        if ($content === false) {
            return null;
        }
        
        $vulnerabilities = [];
        
        // Check for PHP code in images
        if (preg_match('/<\?php/i', $content)) {
            $vulnerabilities[] = [
                'type' => 'malicious_image',
                'pattern' => 'php_code_in_image',
                'severity' => 'high',
            ];
        }
        
        // Check for eval in images
        if (preg_match('/eval\s*\(/i', $content)) {
            $vulnerabilities[] = [
                'type' => 'malicious_image',
                'pattern' => 'eval_in_image',
                'severity' => 'high',
            ];
        }
        
        if (!empty($vulnerabilities)) {
            $relativePath = str_replace($wpPath . '/', '', $filePath);
            $this->log("  [INFECTED IMAGE] $relativePath", 'error');
            
            return [
                'file' => $filePath,
                'relative_path' => $relativePath,
                'vulnerabilities' => $vulnerabilities,
                'file_size' => filesize($filePath),
                'permissions' => substr(sprintf('%o', fileperms($filePath)), -4),
                'modified_date' => date('Y-m-d H:i:s', filemtime($filePath)),
            ];
        }
        
        return null;
    }
    
    /**
     * Generate JSON report
     */
    public function generateReport($installations, $outputFile = 'scan_report.json') {
        $report = [
            'scan_date' => date('Y-m-d H:i:s'),
            'total_installations' => count($installations),
            'total_files_scanned' => $this->scannedFiles,
            'total_infected_files' => $this->infectedFiles,
            'scan_duration' => round(microtime(true) - $this->startTime, 2) . 's',
            'installations' => $installations,
        ];
        
        $json = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        
        if (file_put_contents($outputFile, $json)) {
            $this->log("\nReport saved to: $outputFile", 'success');
            return true;
        } else {
            $this->log("\nError: Could not save report to: $outputFile", 'error');
            return false;
        }
    }
    
    /**
     * Delete infected files based on report
     */
    public function deleteInfectedFiles($reportFile) {
        if (!file_exists($reportFile)) {
            $this->log("Error: Report file not found: $reportFile", 'error');
            return false;
        }
        
        $report = json_decode(file_get_contents($reportFile), true);
        
        if (!$report) {
            $this->log("Error: Invalid report file", 'error');
            return false;
        }
        
        $this->log("Starting deletion of infected files...");
        $deleted = 0;
        $failed = 0;
        
        foreach ($report['installations'] as $installation) {
            $this->log("\nProcessing: {$installation['path']}");
            
            foreach ($installation['infected_files'] as $infectedFile) {
                $filePath = $infectedFile['file'];
                
                if (file_exists($filePath)) {
                    // Create backup before deletion
                    $backupPath = $filePath . '.backup.' . date('YmdHis');
                    if (copy($filePath, $backupPath)) {
                        if (unlink($filePath)) {
                            $this->log("  [DELETED] {$infectedFile['relative_path']}", 'success');
                            $deleted++;
                        } else {
                            $this->log("  [FAILED] Could not delete: {$infectedFile['relative_path']}", 'error');
                            $failed++;
                        }
                    } else {
                        $this->log("  [FAILED] Could not create backup for: {$infectedFile['relative_path']}", 'error');
                        $failed++;
                    }
                } else {
                    $this->log("  [SKIP] File not found: {$infectedFile['relative_path']}", 'warning');
                }
            }
        }
        
        $this->log("\n=== Deletion Summary ===");
        $this->log("Deleted: $deleted files", 'success');
        $this->log("Failed: $failed files", $failed > 0 ? 'error' : 'success');
        
        return true;
    }
    
    /**
     * Rename infected files based on report
     */
    public function renameInfectedFiles($reportFile) {
        if (!file_exists($reportFile)) {
            $this->log("Error: Report file not found: $reportFile", 'error');
            return false;
        }
        
        $report = json_decode(file_get_contents($reportFile), true);
        
        if (!$report) {
            $this->log("Error: Invalid report file", 'error');
            return false;
        }
        
        $this->log("Starting renaming of infected files...");
        $renamed = 0;
        $failed = 0;
        
        foreach ($report['installations'] as $installation) {
            $this->log("\nProcessing: {$installation['path']}");
            
            foreach ($installation['infected_files'] as $infectedFile) {
                $filePath = $infectedFile['file'];
                
                if (file_exists($filePath)) {
                    $newPath = $filePath . '.infected.' . date('YmdHis');
                    
                    if (rename($filePath, $newPath)) {
                        $this->log("  [RENAMED] {$infectedFile['relative_path']} -> " . basename($newPath), 'success');
                        $renamed++;
                    } else {
                        $this->log("  [FAILED] Could not rename: {$infectedFile['relative_path']}", 'error');
                        $failed++;
                    }
                } else {
                    $this->log("  [SKIP] File not found: {$infectedFile['relative_path']}", 'warning');
                }
            }
        }
        
        $this->log("\n=== Rename Summary ===");
        $this->log("Renamed: $renamed files", 'success');
        $this->log("Failed: $failed files", $failed > 0 ? 'error' : 'success');
        
        return true;
    }
    
    /**
     * Log message with color coding
     */
    private function log($message, $type = 'info') {
        $colors = [
            'info' => "\033[0;37m",    // White
            'success' => "\033[0;32m", // Green
            'warning' => "\033[0;33m", // Yellow
            'error' => "\033[0;31m",   // Red
        ];
        
        $reset = "\033[0m";
        $color = $colors[$type] ?? $colors['info'];
        
        echo $color . $message . $reset . PHP_EOL;
    }
    
    /**
     * Display help information
     */
    public function displayHelp() {
        echo <<<HELP
WordPress Malware Scanner
==========================

Usage:
  # Detect WordPress installations and cache information
  php scan.php --detect --path /foo/bar
  
  # List detected WordPress installations
  php scan.php --list
  php scan.php --list --cached custom.json
  
  # Scan for infected files (dry run)
  php scan.php --dry --path /foo/bar
    
  # Fix infected files by severity level (website-specific)
  php scan.php --delete-high-severity --website example.com
  php scan.php --quarantine-medium-severity --website example.com
  php scan.php --comment-low-severity --website example.com
  
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
  
  # Use custom cache file
  php scan.php --cached custom.json --reinstall-core --website example.com

Options:
  --detect              Detect WordPress installations and cache info
  --list                List detected WordPress installations from cache
  --dry                 Perform a malware scan without making changes
  --path <path>         Path to scan for WordPress installations
  --reinstall-core      Reinstall WordPress core files
  --reinstall-plugins   Reinstall all free plugins
  --reinstall-plugin    Reinstall specific plugin
  --reinstall-themes    Reinstall all free themes
  --reinstall-theme     Reinstall specific theme
  --reinstall-all       Reinstall core + plugins + themes
  --report <file>       JSON report file to use for operations
  --cached <file>       Cache file path (default: cached.json)
  --website <domain>    Website domain or identifier
  --wp <version>        WordPress version to install (default: current)
  --force               Force reinstall even if version is current
  --only-infected       Only reinstall infected plugins/themes (requires --report)

Fix Actions (requires --website):
  Delete actions (permanently removes files with backup):
    --delete-high-severity      Delete files with high severity vulnerabilities
    --delete-medium-severity    Delete files with medium severity vulnerabilities
    --delete-low-severity       Delete files with low severity vulnerabilities
  
  Quarantine actions (moves files to .quarantined directory):
    --quarantine-high-severity    Quarantine files with high severity vulnerabilities
    --quarantine-medium-severity  Quarantine files with medium severity vulnerabilities
    --quarantine-low-severity     Quarantine files with low severity vulnerabilities
  
  Comment actions (wraps malicious code with warnings and die() statement):
    --comment-high-severity       Comment out code with high severity vulnerabilities
    --comment-medium-severity     Comment out code with medium severity vulnerabilities
    --comment-low-severity        Comment out code with low severity vulnerabilities

Examples:
  # Step 1: Detect WordPress installations
  php scan.php --detect --path /var/www
  
  # Step 1b: List detected installations
  php scan.php --list
  
  # Step 2: Scan for malware
  php scan.php --dry --path /var/www
  
  # Step 3a: Fix high severity issues by deleting files
  php scan.php --delete-high-severity --website example.com
  
  # Step 3b: Quarantine medium severity files for review
  php scan.php --quarantine-medium-severity --website example.com
  
  # Step 3c: Comment out low severity code
  php scan.php --comment-low-severity --website example.com
  
  # Step 4a: Reinstall infected WordPress core
  php scan.php --reinstall-core --website example.com
  
  # Step 4b: Reinstall only infected plugins
  php scan.php --reinstall-plugins --website example.com --only-infected --report scan_report.json
  
  # Full site cleanup
  php scan.php --reinstall-all --website example.com --force
  
  # Reinstall specific plugin
  php scan.php --reinstall-plugin jetpack --website example.com

Notes:
  - Premium plugins/themes are automatically detected and skipped
  - Only free plugins/themes from WordPress.org are reinstalled
  - Backups are created before all destructive operations
  - Use --force to reinstall even if version is up-to-date
  - Quarantined files are tracked in cached.json
  - Fix actions require --website to target specific installation

HELP;
    }
}

// Main execution
if (php_sapi_name() !== 'cli') {
    die("This script must be run from the command line.\n");
}

$scanner = new WordPressMalwareScanner();

// Parse arguments
$options = $scanner->parseArguments($argv);

// Display help if no valid mode
if (!$options['mode']) {
    $scanner->displayHelp();
    exit(1);
}

// Execute based on mode
switch ($options['mode']) {
    case 'detect':
        if (!$options['path']) {
            echo "Error: --path is required for detect mode\n";
            $scanner->displayHelp();
            exit(1);
        }
        
        $scanner->detectAndCacheInstallations($options['path'], $options['cached']);
        break;
        
    case 'list':
        $scanner->listDetectedWebsites($options['cached']);
        break;
        
    case 'scan':
        // Check if cached.json exists first
        $cacheFile = $options['cached'];
        $installations = [];
        
        if (file_exists($cacheFile)) {
            // Load installations from cache
            $cache = json_decode(file_get_contents($cacheFile), true);
            if ($cache && isset($cache['installations'])) {
                foreach ($cache['installations'] as $inst) {
                    $installations[] = $inst['path'];
                }
                echo "✓ Using " . count($installations) . " installation(s) from cache: $cacheFile\n";
            }
        }
        
        // If no cache found, check for --path option
        if (empty($installations)) {
            if (!$options['path']) {
                echo "Error: No cached installations found in '$cacheFile'\n";
                echo "Please provide --path option or run detection first:\n";
                echo "  php scan.php --detect --path /your/path\n";
                $scanner->displayHelp();
                exit(1);
            }
            
            // Use path to find installations
            $installations = $scanner->findWordPressInstallations($options['path']);
        }
        
        $reports = [];
        
        foreach ($installations as $wpPath) {
            $reports[] = $scanner->scanWordPressInstallation($wpPath);
        }
        
        $scanner->generateReport($reports);
        break;
        
    case 'fix':
        if (!$options['website']) {
            echo "Error: --website is required for fix operations\n";
            $scanner->displayHelp();
            exit(1);
        }
        
        $scanner->applyFix(
            $options['website'],
            $options['action'],
            $options['severity'],
            $options['report'],
            $options['cached'],
            $options['no_backup'] ?? false
        );
        break;
        
    case 'reinstall':
        if (!$options['website']) {
            echo "Error: --website is required for reinstall mode\n";
            $scanner->displayHelp();
            exit(1);
        }
        
        $scanner->reinstallWordPressCore($options['website'], $options['cached'], $options['wp_version'], $options['no_backup'] ?? false);
        break;
        
    case 'reinstall-plugins':
        if (!$options['website']) {
            echo "Error: --website is required for reinstall-plugins mode\n";
            $scanner->displayHelp();
            exit(1);
        }
        
        $scanner->reinstallPlugins(
            $options['website'], 
            $options['cached'], 
            null, 
            $options['force'], 
            $options['only_infected'], 
            $options['report'],
            $options['no_backup'] ?? false
        );
        break;
        
    case 'reinstall-plugin':
        if (!$options['website']) {
            echo "Error: --website is required for reinstall-plugin mode\n";
            $scanner->displayHelp();
            exit(1);
        }
        
        if (!$options['plugin_name']) {
            echo "Error: Plugin name is required for reinstall-plugin mode\n";
            $scanner->displayHelp();
            exit(1);
        }
        
        $scanner->reinstallPlugins(
            $options['website'], 
            $options['cached'], 
            $options['plugin_name'], 
            $options['force'], 
            false, 
            null,
            $options['no_backup'] ?? false
        );
        break;
        
    case 'reinstall-themes':
        if (!$options['website']) {
            echo "Error: --website is required for reinstall-themes mode\n";
            $scanner->displayHelp();
            exit(1);
        }
        
        $scanner->reinstallThemes(
            $options['website'], 
            $options['cached'], 
            null, 
            $options['force'], 
            $options['only_infected'], 
            $options['report'],
            $options['no_backup'] ?? false
        );
        break;
        
    case 'reinstall-theme':
        if (!$options['website']) {
            echo "Error: --website is required for reinstall-theme mode\n";
            $scanner->displayHelp();
            exit(1);
        }
        
        if (!$options['theme_name']) {
            echo "Error: Theme name is required for reinstall-theme mode\n";
            $scanner->displayHelp();
            exit(1);
        }
        
        $scanner->reinstallThemes(
            $options['website'], 
            $options['cached'], 
            $options['theme_name'], 
            $options['force'], 
            false, 
            null,
            $options['no_backup'] ?? false
        );
        break;
        
    case 'reinstall-all':
        if (!$options['website']) {
            echo "Error: --website is required for reinstall-all mode\n";
            $scanner->displayHelp();
            exit(1);
        }
        
        $scanner->reinstallAll(
            $options['website'], 
            $options['cached'], 
            $options['wp_version'], 
            $options['force'],
            $options['no_backup'] ?? false
        );
        break;
        
    default:
        $scanner->displayHelp();
        exit(1);
}

exit(0);
