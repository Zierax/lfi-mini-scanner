# LFI-mini Scanner

A comprehensive Python-based Local File Inclusion (LFI) vulnerability scanner designed for educational and authorized penetration testing purposes.

##  Overview

This tool systematically tests web applications for Local File Inclusion vulnerabilities by attempting various directory traversal techniques, encoding methods, and file access patterns. It supports multi-threaded scanning, custom payloads, and comprehensive reporting.

## Features

### Core Capabilities
- **Multi-threaded Scanning** - Concurrent request processing for faster execution
- **60+ Traversal Patterns** - Including URL encoding, Unicode, double encoding, and null bytes
- **PHP Wrapper Support** - Tests php://filter, expect://, data://, phar://, and zip:// protocols
- **35+ File Signatures** - Detects Windows, Linux, Apache, Nginx, PHP, and configuration files
- **Smart Pattern Matching** - Regex-based content verification to reduce false positives

### Advanced Options
- **Session Cookie Support** - Test authenticated endpoints
- **Custom User-Agent** - Randomized or user-defined headers
- **Request Rate Limiting** - Configurable delays between requests
- **Redirect Handling** - Optional redirect following
- **Null Byte Injection** - Tests legacy PHP null byte vulnerabilities
- **JSON Export** - Save findings in structured format
- **Verbose Mode** - Detailed output for debugging

### Performance Features
- **Concurrent Threading** - 1-50 configurable worker threads
- **Request Timeout** - Prevent hanging on slow targets
- **URL Deduplication** - Avoid testing identical payloads
- **Response Time Tracking** - Performance metrics per request

## 📋 Requirements

```
Python 3.7+
requests
urllib3
```

## Installation

```bash
git clone https://github.com/Zierax/lfi-mini-scanner.git
cd lfi-mini-scanner
pip install -r requirements.txt
```

### requirements.txt
```
requests>=2.28.0
urllib3>=1.26.0
```

## 💻 Usage

### Basic Scan
```bash
python3 lfi-mini-scanner.py -u "http://target.com/page.php?file=document.pdf" -s "document.pdf"
```

### Authenticated Scan with Cookie
```bash
python3 lfi-mini-scanner.py -u "http://target.com/admin.php?page=home" -s "home" -c "PHPSESSID=abc123xyz"
```

### Deep Scan with Maximum Depth
```bash
python3 lfi-mini-scanner.py -u "http://target.com/view?doc=file.txt" -s "file.txt" -d 10 -t 20
```

### Verbose Mode with JSON Output
```bash
python3 lfi-mini-scanner.py -u "http://target.com/?include=page" -s "page" -v -o results.json
```

### Null Byte Injection Test
```bash
python3 lfi-mini-scanner.py -u "http://target.com/read.php?file=data.txt" -s "data.txt" -n
```

### Rate-Limited Scan
```bash
python3 lfi-mini-scanner.py -u "http://target.com/show?path=info" -s "info" --delay 0.5 -t 5
```

## Command-Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--url` | `-u` | Target URL with parameter to test (required) | - |
| `--string` | `-s` | String to replace in URL (required) | - |
| `--cookie` | `-c` | Session cookie for authentication | None |
| `--depth` | `-d` | Directory traversal depth | 6 |
| `--threads` | `-t` | Number of concurrent threads | 10 |
| `--timeout` | - | Request timeout in seconds | 10 |
| `--user-agent` | - | Custom User-Agent string | Random |
| `--delay` | - | Delay between requests (seconds) | 0.0 |
| `--output` | `-o` | Output file for results (JSON) | None |
| `--null-byte` | `-n` | Enable null byte injection tests | False |
| `--follow-redirects` | `-r` | Follow HTTP redirects | False |
| `--verbose` | `-v` | Enable verbose output mode | False |

## Examples

### Example 1: Testing a Simple Parameter
```bash
python3 lfi-mini-scanner.py -u "http://example.com/index.php?page=home.php" -s "home.php" -d 8
```

### Example 2: Testing with Authentication
```bash
python3 lfi-mini-scanner.py \
  -u "http://example.com/dashboard?file=report.pdf" \
  -s "report.pdf" \
  -c "session=eyJhbGciOiJIUzI1NiJ9; token=xyz123" \
  -t 15 \
  -v
```

### Example 3: Comprehensive Scan with Export
```bash
python3 lfi-mini-scanner.py \
  -u "http://example.com/view.php?document=file.txt" \
  -s "file.txt" \
  -d 12 \
  -t 20 \
  --null-byte \
  --follow-redirects \
  --delay 0.2 \
  -o vulnerability_report.json \
  -v
```

### Example 4: Stealth Scan with Rate Limiting
```bash
python3 lfi-mini-scanner.py \
  -u "http://example.com/read?path=data.xml" \
  -s "data.xml" \
  -t 3 \
  --delay 1.0 \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

##  Output Format

### Console Output
The scanner provides color-coded output:
- **Green** - Successful findings (2xx status)
- **Yellow** - Redirects (3xx status)
- **Red** - Client errors (4xx status)
- **Blue** - Server errors (5xx status)

### JSON Output Format
```json
{
  "scan_info": {
    "target_url": "http://example.com/page.php?file=doc.pdf",
    "target_param": "doc.pdf",
    "depth": 6,
    "total_requests": 2450,
    "vulnerabilities_found": 3,
    "timestamp": "2025-11-25 14:30:45"
  },
  "findings": [
    {
      "url": "http://example.com/page.php?file=../../etc/passwd",
      "status_code": 200,
      "file_target": "etc/passwd",
      "matches": 15,
      "response_time": 0.34,
      "content_length": 2048
    }
  ]
}
```

## 🔬 Detection Patterns

### Windows Files
- `c:\boot.ini`
- `c:\windows\win.ini`
- `c:\windows\system32\drivers\etc\hosts`

### Linux Files
- `/etc/passwd`
- `/etc/shadow`
- `/etc/hosts`
- `/etc/group`
- `/proc/self/environ`
- `/proc/version`

### Web Server Configs
- `/etc/apache2/apache2.conf`
- `/etc/nginx/nginx.conf`
- `.htaccess`
- `.htpasswd`

### Application Files
- `index.php`
- `config.php`
- `wp-config.php`
- `.env`
- `composer.json`
- `package.json`

### Log Files
- `/var/log/apache2/access.log`
- `/var/log/nginx/error.log`

##  Security Best Practices

### For Penetration Testers
1. Always obtain written authorization before testing
2. Document all findings professionally
3. Use rate limiting to avoid DoS conditions
4. Test during approved maintenance windows
5. Report vulnerabilities responsibly

### For Developers
1. Never trust user input
2. Implement whitelist-based file access
3. Use absolute paths instead of relative paths
4. Disable PHP wrappers if not needed
5. Validate and sanitize all file parameters
6. Implement proper access controls
7. Log and monitor file access attempts

## 🔧 Configuration

### Adjusting Thread Count
For faster scans on powerful systems:
```bash
python3 lfi-mini-scanner.py -u "URL" -s "STRING" -t 30
```

For slower, stealthier scans:
```bash
python3 lfi-mini-scanner.py -u "URL" -s "STRING" -t 3 --delay 2.0
```

### Increasing Traversal Depth
For deeply nested directories:
```bash
python3 lfi-mini-scanner.py -u "URL" -s "STRING" -d 15
```

##  Performance Tips

1. **Optimal Thread Count**: 10-20 threads for most targets
2. **Network Latency**: Increase timeout for slow networks
3. **Large Scans**: Use `--output` to save results progressively
4. **Rate Limiting**: Use `--delay` to avoid triggering WAF/IDS
5. **Verbose Mode**: Disable in production scans for better performance

##  Troubleshooting

### SSL Certificate Errors
The scanner disables SSL verification by default. For strict SSL:
```python
response = self.session.get(url, verify=True)
```

### Connection Timeouts
Increase timeout value:
```bash
python3 lfi-mini-scanner.py -u "URL" -s "STRING" --timeout 30
```

### Too Many Threads
Reduce concurrent connections:
```bash
python3 lfi-mini-scanner.py -u "URL" -s "STRING" -t 5
```

## Resources

- [OWASP LFI Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [PortSwigger LFI Tutorial](https://portswigger.net/web-security/file-path-traversal)
- [HackTricks LFI Techniques](https://book.hacktricks.xyz/pentesting-web/file-inclusion)

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description
