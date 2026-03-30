#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║  Red Recce — Bug Bounty Orchestrator                     ║
║  Kali Linux Live USB Edition                             ║
║  apt-only tools · low RAM · sequential execution         ║
╚══════════════════════════════════════════════════════════╝

Install all tools (one-liner, safe on live USB):
  sudo apt install -y nmap sqlmap ffuf nikto gobuster nuclei \
    subfinder httpx-toolkit whatweb wafw00f dnsrecon curl

Usage:
  python3 redrecce.py -t target.com
  python3 redrecce.py -t localhost:3000        # Juice Shop
  python3 redrecce.py -t target.com --phase recon
  python3 redrecce.py -t target.com --phase all
  python3 redrecce.py -t target.com --resume
  python3 redrecce.py -t target.com --proxy http://127.0.0.1:8080
  python3 redrecce.py -t target.com --dry-run
  python3 redrecce.py --check-tools

Phases:
  recon      DNS + subdomain enum: dnsrecon, subfinder
  probe      Live host + tech detect: httpx-toolkit, whatweb, wafw00f
  portscan   Port + service scan: nmap
  crawl      Directory brute-force: gobuster / ffuf
  vulnscan   Vuln templates: nuclei + nikto
  xss        XSS scan: nuclei XSS templates
  sqli       SQL injection: sqlmap
  all        All phases in sequence (default)
"""

import argparse
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

# ── ANSI ──────────────────────────────────────────────────────────────────────
R       = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
GRAY    = "\033[90m"
DKGRAY  = "\033[38;5;236m"
DKRED   = "\033[38;5;160m"
BRTRED  = "\033[38;5;196m"

LOGO = (
    f"\n"
    # ── R  E  D ── (each letter = 8 cols, centred)
    f"  {DKRED}                ██████╗ ███████╗██████╗ {R}\n"
    f"  {DKRED}                ██╔══██╗██╔════╝██╔══██╗{R}\n"
    f"  {DKRED}                ██████╔╝█████╗  ██║  ██║{R}\n"
    f"  {BRTRED}                ██╔══██╗██╔══╝  ██║  ██║{R}\n"
    f"  {BRTRED}                ██║  ██║███████╗██████╔╝ {R}\n"
    f"\n"
    # ── R  E  C  C  E ── (5 × 8 cols = 40 cols)
    f"  {BRTRED}  ██████╗ ███████╗ ██████╗  ██████╗ ███████╗{R}\n"
    f"  {DKRED}  ██╔══██╗██╔════╝██╔════╝ ██╔════╝ ██╔════╝{R}\n"
    f"  {BRTRED}  ██████╔╝█████╗  ██║      ██║      █████╗  {R}\n"
    f"  {DKRED}  ██╔══██╗██╔══╝  ██║      ██║      ██╔══╝  {R}\n"
    f"  {BRTRED}  ██║  ██║███████╗╚██████╗ ╚██████╗ ███████╗{R}\n"
    f"\n"
    f"{DKGRAY}{BOLD}╔══════════════════════════════════════════════════════════╗\n"
    f"║  {GRAY}── Kali Live USB ·  apt-only ·  low-RAM edition ──{DKGRAY}        ║\n"
    f"║  {GRAY}nmap · sqlmap · ffuf · nuclei · nikto · gobuster{DKGRAY}          ║\n"
    f"║  {GRAY}subfinder · httpx · whatweb · wafw00f · dnsrecon{DKGRAY}          ║\n"
    f"╚══════════════════════════════════════════════════════════╝{R}\n"
)

PHASE_ORDER = ["recon", "probe", "portscan", "crawl", "vulnscan", "xss", "sqli"]

PHASE_META = {
    "recon":    ("🔍", "DNS & Subdomain Recon",      ["dnsrecon", "subfinder"]),
    "probe":    ("📡", "Live Host & Tech Detection", ["httpx-toolkit", "whatweb", "wafw00f"]),
    "portscan": ("🔌", "Port & Service Scan",         ["nmap"]),
    "crawl":    ("💣", "Directory Brute-Force",       ["gobuster", "ffuf"]),
    "vulnscan": ("☢ ", "Vulnerability Scan",          ["nuclei", "nikto"]),
    "xss":      ("🪃", "XSS Scanning",                ["nuclei"]),
    "sqli":     ("💉", "SQL Injection",                ["sqlmap"]),
}

# apt install commands — no Go, no compilation
TOOL_APT = {
    "nmap":          "sudo apt install -y nmap",
    "sqlmap":        "sudo apt install -y sqlmap",
    "ffuf":          "sudo apt install -y ffuf",
    "nikto":         "sudo apt install -y nikto",
    "gobuster":      "sudo apt install -y gobuster",
    "nuclei":        "sudo apt install -y nuclei",
    "subfinder":     "sudo apt install -y subfinder",
    "httpx-toolkit": "sudo apt install -y httpx-toolkit",
    "whatweb":       "sudo apt install -y whatweb",
    "wafw00f":       "sudo apt install -y wafw00f",
    "dnsrecon":      "sudo apt install -y dnsrecon",
    "curl":          "sudo apt install -y curl",
}

# Default dnsrecon brute-force wordlist on Kali
DNSRECON_WORDLIST = "/usr/share/dnsrecon/namelist.txt"

_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(?::\d{1,5})?$'   # allow port like localhost:3000
)

# Loopback hosts — skip DNS/subdomain enum for these
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

# ── Print helpers ─────────────────────────────────────────────────────────────

def banner():       print(LOGO)
def hdr(msg):
    print(f"\n{DKGRAY}{BOLD}{'─'*58}{R}")
    print(f"{RED}{BOLD}  {msg}{R}")
    print(f"{DKGRAY}{BOLD}{'─'*58}{R}\n")
def ok(msg):        print(f"  {GREEN}✓{R}  {msg}")
def info(msg):      print(f"  {CYAN}→{R}  {msg}")
def warn(msg):      print(f"  {YELLOW}⚠{R}  {msg}")
def err(msg):       print(f"  {RED}✗{R}  {msg}", file=sys.stderr)
def dim(msg):       print(f"  {GRAY}{msg}{R}")

def section(icon, title, color=RED):
    print(f"\n{color}{BOLD}  {icon} {title}{R}")
    print(f"  {DKGRAY}{'─'*52}{R}")

# ── Validation ────────────────────────────────────────────────────────────────

def validate_target(raw: str) -> str:
    t = re.sub(r'^https?://', '', raw.strip(), flags=re.IGNORECASE)
    t = t.split('/')[0].split('?')[0].split('#')[0].rstrip('.')
    if not t:
        raise ValueError("Target is empty.")
    if not _DOMAIN_RE.match(t):
        raise ValueError(
            f"Invalid target '{t}'.\n"
            "  Use a hostname like target.com or localhost:3000"
        )
    return t

def target_base(t: str) -> str:
    """Return just the host without port."""
    return t.split(':')[0]

def target_port(t: str) -> str | None:
    """Return port if specified."""
    parts = t.split(':')
    return parts[1] if len(parts) > 1 else None

def target_url(t: str, scheme: str = "http") -> str:
    """Build a full URL from target."""
    port = target_port(t)
    host = target_base(t)
    if port:
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"

# ── Tool helpers ──────────────────────────────────────────────────────────────

def check_tool(name: str) -> bool:
    # httpx may be installed as httpx or httpx-toolkit
    if name == "httpx-toolkit":
        return shutil.which("httpx") is not None or shutil.which("httpx-toolkit") is not None
    return shutil.which(name) is not None

def httpx_bin() -> str:
    if shutil.which("httpx"):
        return "httpx"
    if shutil.which("httpx-toolkit"):
        return "httpx-toolkit"
    return "httpx"

# ── Subprocess helpers ────────────────────────────────────────────────────────

def run(cmd: str, timeout: int | None = None) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout,
            encoding='utf-8', errors='replace'
        )
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -1, "", str(e)

def run_live(cmd: str, logfile: str | None = None,
             timeout: int | None = None, dry_run: bool = False) -> int:
    if dry_run:
        print(f"  {YELLOW}[DRY-RUN]{R} {GRAY}$ {cmd}{R}\n")
        return 0
    print(f"  {GRAY}$ {cmd}{R}\n")
    try:
        proc = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
            encoding='utf-8', errors='replace'
        )
    except OSError as e:
        err(f"Failed to launch: {e}")
        return -1

    if proc.stdout is None:
        proc.wait()
        return proc.returncode

    lf = None
    if logfile:
        try:
            d = os.path.dirname(logfile)
            if d:
                os.makedirs(d, exist_ok=True)
            lf = open(logfile, 'w', encoding='utf-8', errors='replace')
        except OSError as e:
            warn(f"Cannot open logfile {logfile}: {e}")

    deadline = time.time() + timeout if timeout else None

    try:
        for line in iter(proc.stdout.readline, ''):
            line = line.rstrip()
            if line:
                print(f"  {DIM}{line}{R}")
                if lf:
                    lf.write(line + '\n')
                    lf.flush()
            if deadline and time.time() > deadline:
                warn(f"Timeout ({timeout}s) — killing process")
                proc.kill()
                proc.wait()
                return -1
    finally:
        if lf:
            try: lf.close()
            except Exception: pass

    proc.wait()
    return proc.returncode

# ── File helpers ──────────────────────────────────────────────────────────────

def read_lines(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            return [l.strip() for l in f if l.strip()]
    except OSError:
        return []

def write_lines(path: str, lines: list[str]) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + ('\n' if lines else ''))

def count_lines(path: str) -> int:
    return len(read_lines(path))

def dedup_file(path: str) -> int:
    lines = list(dict.fromkeys(read_lines(path)))
    write_lines(path, lines)
    return len(lines)

def rm_f(path: str) -> None:
    if os.path.exists(path):
        os.remove(path)

# ── State ─────────────────────────────────────────────────────────────────────

class State:
    def __init__(self, outdir: str):
        self.path = os.path.join(outdir, ".redrecce_state.json")
        self.data = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.path):
            try:
                with open(self.path, encoding='utf-8') as f:
                    d = json.load(f)
                d.setdefault("completed", [])
                d.setdefault("findings", {})
                return d
            except (json.JSONDecodeError, OSError) as e:
                warn(f"State file corrupt ({e}), starting fresh.")
        return {"completed": [], "findings": {}}

    def save(self) -> None:
        tmp = self.path + ".tmp"
        try:
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=2)
            os.replace(tmp, self.path)
        except OSError as e:
            warn(f"Could not save state: {e}")

    def mark_done(self, phase: str) -> None:
        if phase not in self.data["completed"]:
            self.data["completed"].append(phase)
        self.save()

    def is_done(self, phase: str) -> bool:
        return phase in self.data["completed"]

    def set(self, phase: str, key: str, value) -> None:
        self.data["findings"].setdefault(phase, {})[key] = value
        self.save()

    def get(self, phase: str, key: str, default=None):
        return self.data["findings"].get(phase, {}).get(key, default)

# ── nmap XML parser ───────────────────────────────────────────────────────────

def parse_nmap_xml(xml_path: str) -> list[dict]:
    hosts = []
    if not os.path.exists(xml_path):
        return hosts
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as e:
        warn(f"nmap XML parse error: {e}")
        return hosts
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue
        addr_el = host_el.find("address")
        ip = addr_el.get("addr", "") if addr_el is not None else ""
        hn_el = host_el.find("hostnames/hostname")
        name  = hn_el.get("name", "") if hn_el is not None else ""
        ports = []
        for p in host_el.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            ports.append({
                "port":    p.get("portid", ""),
                "proto":   p.get("protocol", "tcp"),
                "service": svc.get("name", "")    if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
            })
        hosts.append({"ip": ip, "name": name, "ports": ports})
    return hosts

# ── Severity table ────────────────────────────────────────────────────────────

def sev_table(counts: dict, title: str = "") -> None:
    total = sum(counts.values())
    if not total:
        return
    if title:
        print(f"\n  {BOLD}{title}{R}")
    print(f"  {DKGRAY}{'─'*40}{R}")
    _sev_order = ["critical", "high", "medium", "low", "info"]
    colors = {"critical": RED+BOLD, "high": RED, "medium": YELLOW,
              "low": CYAN, "info": GRAY}
    for k, n in sorted(counts.items(),
                       key=lambda x: _sev_order.index(x[0]) if x[0] in _sev_order else 99):
        c = colors.get(k, GRAY)
        bar = "█" * min(n, 28)
        print(f"  {c}{k.upper():<12}{R} {c}{n:>4}{R}  {GRAY}{bar}{R}")
    print(f"  {'─'*40}")
    print(f"  {'TOTAL':<12} {BOLD}{total:>4}{R}\n")

# ── Red Recce ─────────────────────────────────────────────────────────────────

class HuntKit:
    def __init__(self, args):
        self.target   = validate_target(args.target)
        self.host     = target_base(self.target)
        self.port     = target_port(self.target)
        self.args     = args
        self.rate     = args.rate
        self.threads  = args.threads
        self.proxy    = args.proxy
        self.dry_run  = args.dry_run
        safe_name     = self.target.replace(':', '_').replace('/', '_')
        self.outdir   = os.path.join(args.output, safe_name)
        self.wordlist = args.wordlist or self._find_wordlist()
        self._setup_dirs()
        self.state    = State(self.outdir)
        self.start_t  = time.time()

    @property
    def is_local(self) -> bool:
        """True for loopback targets where DNS/subdomain enum makes no sense."""
        return self.host in _LOCAL_HOSTS

    def _find_wordlist(self) -> str | None:
        for p in [
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
        ]:
            if os.path.exists(p):
                return p
        return None

    def _setup_dirs(self) -> None:
        for d in ["recon","probe","portscan","crawl","vulnscan","xss","sqli","logs","report"]:
            Path(os.path.join(self.outdir, d)).mkdir(parents=True, exist_ok=True)

    def f(self, *parts) -> str:
        return os.path.join(self.outdir, *parts)

    def rl(self, cmd: str, log: str, timeout: int | None = None) -> int:
        return run_live(cmd, logfile=self.f("logs", log),
                        timeout=timeout, dry_run=self.dry_run)

    def proxy_flag(self, style: str = "") -> str:
        if not self.proxy:
            return ""
        p = shlex.quote(self.proxy)
        if style == "sqlmap":  return f"--proxy={p}"
        if style == "nikto":   return f"-useproxy {self.proxy}"
        if style == "curl":    return f"-x {self.proxy}"
        return f"-proxy {p}"

    def url(self, scheme: str = "http") -> str:
        return target_url(self.target, scheme)

    # ── Check tools ───────────────────────────────────────────────────────────

    def check_tools(self, phase: str = "all") -> list[str]:
        section("🔧", "Tool Check")
        if phase != "all":
            needed = list(PHASE_META.get(phase, ("", "", []))[2])
        else:
            needed = list({t for v in PHASE_META.values() for t in v[2]})

        missing = []
        for t in sorted(needed):
            if check_tool(t):
                ok(f"{t}")
            else:
                warn(f"{t}  {GRAY}→ install: {TOOL_APT.get(t, 'sudo apt install -y ' + t)}{R}")
                missing.append(t)
        return missing

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 1 — Recon
    # ─────────────────────────────────────────────────────────────────────────

    def phase_recon(self) -> str:
        section("🔍", "Phase 1 — DNS & Subdomain Recon", RED)
        merged = self.f("recon", "subdomains.txt")
        rm_f(merged)
        all_subs: set[str] = {self.host}

        if self.is_local:
            info("Loopback target — skipping DNS/subdomain enum")
        else:
            # dnsrecon — basic DNS enum
            if check_tool("dnsrecon"):
                out = self.f("recon", "dnsrecon.json")
                info("Running dnsrecon...")
                # Use std + brt; supply default Kali wordlist for brt type
                brt_flag = ""
                if os.path.exists(DNSRECON_WORDLIST):
                    brt_flag = f"-D {shlex.quote(DNSRECON_WORDLIST)}"
                    scan_types = "std,brt"
                else:
                    scan_types = "std"
                cmd = (
                    f"dnsrecon -d {shlex.quote(self.host)} "
                    f"-t {scan_types} "
                    f"--lifetime 5 "
                    f"-j {shlex.quote(out)} "
                    f"{brt_flag}"
                )
                self.rl(cmd, "dnsrecon.log", timeout=120)
                if os.path.exists(out):
                    try:
                        with open(out, encoding='utf-8', errors='replace') as fh:
                            data = json.load(fh)
                        for rec in (data if isinstance(data, list) else []):
                            n = rec.get("name", "") or rec.get("target", "")
                            if n and self.host in n:
                                all_subs.add(n.rstrip('.'))
                    except (json.JSONDecodeError, OSError):
                        pass
                ok("dnsrecon done")
            else:
                warn("dnsrecon not found  →  sudo apt install -y dnsrecon")

            # subfinder
            if check_tool("subfinder"):
                sf_out = self.f("recon", "subfinder.txt")
                info("Running subfinder...")
                proxy_flag = f"-proxy {shlex.quote(self.proxy)}" if self.proxy else ""
                cmd = (
                    f"subfinder -d {shlex.quote(self.host)} "
                    f"-o {shlex.quote(sf_out)} "
                    f"-silent {proxy_flag}"
                )
                self.rl(cmd, "subfinder.log", timeout=120)
                subs = read_lines(sf_out)
                all_subs.update(subs)
                ok(f"subfinder → {len(subs)} subdomains")
            else:
                warn("subfinder not found  →  sudo apt install -y subfinder")

        write_lines(merged, sorted(all_subs))
        total = dedup_file(merged)
        self.state.set("recon", "subdomain_count", total)
        self.state.set("recon", "subdomains_file", merged)
        ok(f"Total subdomains: {CYAN}{BOLD}{total}{R}")
        sev_table({"subdomains": total}, "Recon summary")
        self.state.mark_done("recon")
        return merged

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 2 — Probe
    # ─────────────────────────────────────────────────────────────────────────

    def phase_probe(self) -> str:
        section("📡", "Phase 2 — Live Host & Tech Detection", RED)
        urls_out = self.f("probe", "urls.txt")
        rm_f(urls_out)

        # Build target list from subdomains or just use target
        subs_file = self.f("recon", "subdomains.txt")
        targets   = read_lines(subs_file) if os.path.exists(subs_file) else [self.host]
        if not targets:
            targets = [self.host]

        live_urls: list[str] = []

        # httpx
        hx = httpx_bin()
        if check_tool("httpx-toolkit"):
            targets_file = self.f("probe", "probe_targets.txt")
            write_lines(targets_file, targets)
            info(f"Probing {len(targets)} host(s) with {hx}...")
            jsonl_out = self.f("probe", "httpx.jsonl")
            rm_f(jsonl_out)
            # Always probe the explicit port when specified
            port_flag = f"-ports {self.port}" if self.port else ""
            cmd = (
                f"{hx} -l {shlex.quote(targets_file)} "
                f"-status-code -title -tech-detect -follow-redirects "
                f"-threads {self.threads} "
                f"-json -o {shlex.quote(jsonl_out)} "
                f"-silent {port_flag} "
                f"{self.proxy_flag()}"
            )
            self.rl(cmd, "httpx.log", timeout=120)
            # Extract URLs from JSONL output
            if os.path.exists(jsonl_out):
                for line in read_lines(jsonl_out):
                    try:
                        e = json.loads(line)
                        u = e.get("url") or e.get("input", "")
                        if u:
                            live_urls.append(u)
                    except json.JSONDecodeError:
                        pass
            # Fallback: probe base target directly with curl
            if not live_urls:
                for scheme in ("http", "https"):
                    u = target_url(self.target, scheme)
                    rc, _, _ = run(f"curl -sI --max-time 5 {shlex.quote(u)}", timeout=10)
                    if rc == 0:
                        live_urls.append(u)
        else:
            warn(f"{hx} not found  →  sudo apt install -y httpx-toolkit")
            # Fallback: curl check
            for scheme in ("http", "https"):
                u = target_url(self.target, scheme)
                info(f"Probing {u} with curl...")
                rc, _, _ = run(f"curl -sI --max-time 5 {shlex.quote(u)}", timeout=10)
                if rc == 0:
                    live_urls.append(u)
                    ok(f"Live: {u}")

        if not live_urls:
            warn("No live hosts found — adding base target as fallback")
            live_urls = [target_url(self.target, "http")]

        write_lines(urls_out, live_urls)
        ok(f"Live URLs: {CYAN}{BOLD}{len(live_urls)}{R}")

        # whatweb — tech fingerprint (use run() to capture output cleanly)
        if check_tool("whatweb"):
            info("Running whatweb...")
            ww_out = self.f("probe", "whatweb.txt")
            ww_lines: list[str] = []
            for u in live_urls[:3]:
                rc, stdout, stderr = run(
                    f"whatweb --no-errors -a 3 {shlex.quote(u)}",
                    timeout=30,
                )
                combined = (stdout + stderr).strip()
                if combined:
                    ww_lines.append(combined)
            if ww_lines:
                write_lines(ww_out, ww_lines)
            ok("whatweb done")
        else:
            warn("whatweb not found  →  sudo apt install -y whatweb")

        # wafw00f — WAF detection (use run() to capture output cleanly)
        if check_tool("wafw00f"):
            info("Running wafw00f...")
            waf_out = self.f("probe", "wafw00f.txt")
            waf_lines: list[str] = []
            for u in live_urls[:3]:
                rc, stdout, stderr = run(
                    f"wafw00f {shlex.quote(u)}",
                    timeout=30,
                )
                combined = (stdout + stderr).strip()
                if combined:
                    waf_lines.append(combined)
            if waf_lines:
                write_lines(waf_out, waf_lines)
            ok("wafw00f done")
        else:
            warn("wafw00f not found  →  sudo apt install -y wafw00f")

        self.state.set("probe", "live_count", len(live_urls))
        self.state.set("probe", "urls_file", urls_out)
        sev_table({"live": len(live_urls), "targets": len(targets)}, "Probe summary")
        self.state.mark_done("probe")
        return urls_out

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 3 — Port Scan
    # ─────────────────────────────────────────────────────────────────────────

    def phase_portscan(self) -> None:
        section("🔌", "Phase 3 — Port & Service Scan", RED)
        if not check_tool("nmap"):
            err("nmap not found  →  sudo apt install -y nmap")
            return

        nmap_base = self.f("portscan", "nmap")
        nmap_xml  = nmap_base + ".xml"
        for ext in (".xml", ".gnmap", ".nmap"):
            rm_f(nmap_base + ext)

        # Localhost gets a faster timing; remote hosts more conservative
        port_arg = f"-p {self.port}" if self.port else "--top-ports 1000"
        timing   = "-T4" if self.is_local else "-T3"

        info(f"Scanning {self.host} ({port_arg})...")
        cmd = (
            f"nmap {shlex.quote(self.host)} "
            f"{port_arg} "
            f"-sV --version-intensity 5 "
            f"{timing} "
            f"-oA {shlex.quote(nmap_base)} "
            f"--open"
        )
        rc = self.rl(cmd, "nmap.log", timeout=300)
        if rc == -1:
            warn("nmap timed out  →  try: --phase portscan alone")

        # Parse and display results
        hosts = parse_nmap_xml(nmap_xml)
        total_ports = 0
        if hosts:
            print(f"\n  {BOLD}Open ports:{R}")
            print(f"  {DKGRAY}{'─'*50}{R}")
            for h in hosts:
                for p in h["ports"]:
                    ver = f"{p['product']} {p['version']}".strip() or p["service"]
                    c   = RED if p["port"] in ("22", "3389", "5900") else \
                          YELLOW if p["port"] in ("80", "443", "8080", "8443", "3000") else GRAY
                    print(f"  {c}{p['port']}/{p['proto']:<4}{R}  {p['service']:<14}  {GRAY}{ver}{R}")
                    total_ports += 1
            print()
            with open(self.f("portscan", "summary.json"), 'w', encoding='utf-8') as fh:
                json.dump(hosts, fh, indent=2)
            self.state.set("portscan", "open_port_count", total_ports)
        elif not self.dry_run:
            if os.path.exists(nmap_xml):
                ok("nmap complete — no open ports found")
            else:
                warn(
                    "nmap XML not found — check logs/nmap.log\n"
                    "  Note: SYN scan needs root. Try: sudo python3 redrecce.py …"
                )

        self.state.mark_done("portscan")

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 4 — Crawl / Directory Brute-Force
    # ─────────────────────────────────────────────────────────────────────────

    def phase_crawl(self) -> None:
        section("💣", "Phase 4 — Directory Brute-Force", RED)

        if not self.wordlist:
            err(
                "No wordlist found.\n"
                "  Install: sudo apt install -y seclists\n"
                "  Or:      sudo apt install -y dirb\n"
                "  Or:      --wordlist /path/to/list.txt"
            )
            return

        urls_file = self.f("probe", "urls.txt")
        targets   = read_lines(urls_file) if os.path.exists(urls_file) else [target_url(self.target)]
        if not targets:
            targets = [target_url(self.target)]
        targets = targets[:3]  # cap — RAM safety

        wl_count = count_lines(self.wordlist)
        info(f"Wordlist: {self.wordlist} ({wl_count} entries)")

        all_hits: list[dict] = []
        status_counts: dict[int, int] = {}

        for i, base_url in enumerate(targets, 1):
            base_url = base_url.rstrip("/")
            info(f"[{i}/{len(targets)}] {CYAN}{base_url}{R}")

            # gobuster first (lower RAM than ffuf)
            if check_tool("gobuster"):
                gb_out = self.f("crawl", f"gobuster_{i}.txt")
                rm_f(gb_out)
                proxy_flag = f"--proxy {shlex.quote(self.proxy)}" if self.proxy else ""
                cmd = (
                    f"gobuster dir "
                    f"-u {shlex.quote(base_url)} "
                    f"-w {shlex.quote(self.wordlist)} "
                    f"-o {shlex.quote(gb_out)} "
                    f"-t {self.threads} "
                    f"-q "
                    f"--no-error "
                    f"-s 200,201,204,301,302,307,401,403 "
                    f"{proxy_flag}"
                )
                rc = self.rl(cmd, f"gobuster_{i}.log", timeout=300)
                if rc == -1:
                    warn(f"gobuster timed out on {base_url}")
                for line in read_lines(gb_out):
                    # gobuster v3 format: /path (Status: 200) [Size: 1234]
                    m = re.match(r'(/\S*)\s+\(Status:\s*(\d+)\)', line)
                    if m:
                        path, sc = m.group(1), int(m.group(2))
                        all_hits.append({"host": base_url, "path": path, "status": sc})
                        status_counts[sc] = status_counts.get(sc, 0) + 1

            # ffuf fallback when gobuster is unavailable
            elif check_tool("ffuf"):
                ff_out = self.f("crawl", f"ffuf_{i}.json")
                rm_f(ff_out)
                proxy_flag = self.proxy_flag() if self.proxy else ""
                cmd = (
                    f"ffuf -u {shlex.quote(base_url + '/FUZZ')} "
                    f"-w {shlex.quote(self.wordlist)} "
                    f"-mc 200,201,204,301,302,307,401,403 "
                    f"-t {self.threads} "
                    f"-rate {self.rate} "
                    f"-o {shlex.quote(ff_out)} -of json "
                    f"-s "
                    f"{proxy_flag}"
                )
                rc = self.rl(cmd, f"ffuf_{i}.log", timeout=300)
                if rc == -1:
                    warn(f"ffuf timed out on {base_url}")
                if os.path.exists(ff_out):
                    try:
                        with open(ff_out, encoding='utf-8', errors='replace') as fh:
                            data = json.load(fh)
                        for r in data.get("results", []):
                            sc   = r.get("status", 0)
                            path = "/" + r.get("input", {}).get("FUZZ", "")
                            all_hits.append({"host": base_url, "path": path, "status": sc})
                            status_counts[sc] = status_counts.get(sc, 0) + 1
                    except (json.JSONDecodeError, OSError):
                        pass
            else:
                warn(
                    "Neither gobuster nor ffuf found\n"
                    "  Install: sudo apt install -y gobuster ffuf"
                )

        # Save all hits
        hits_out = self.f("crawl", "hits.txt")
        write_lines(hits_out, [f"{h['status']} {h['host']}{h['path']}" for h in all_hits])

        # Build params.txt for XSS/SQLi phases
        params: list[str] = []
        for h in all_hits[:30]:
            params.append(h["host"] + h["path"])
        # Augment with common param patterns on each live target
        for base_url in targets:
            for ep in [
                "/search?q=", "/login?redirect=", "/profile?id=",
                "/?id=", "/?search=", "/?page=", "/?cat=", "/?file=",
                "/rest/products/search?q=",     # Juice Shop
                "/api/user?id=",
            ]:
                params.append(base_url.rstrip("/") + ep)
        params_out = self.f("crawl", "params.txt")
        write_lines(params_out, list(dict.fromkeys(params)))

        ok(f"Paths found:   {CYAN}{BOLD}{len(all_hits)}{R}")
        ok(f"Param URLs:    {CYAN}{BOLD}{len(params)}{R}")

        if status_counts:
            sev_table({f"HTTP {sc}": n for sc, n in status_counts.items()},
                      "Crawl results by status")

        self.state.set("crawl", "hit_count", len(all_hits))
        self.state.set("crawl", "params_file", params_out)
        self.state.mark_done("crawl")

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 5 — Vuln Scan
    # ─────────────────────────────────────────────────────────────────────────

    def phase_vulnscan(self) -> None:
        section("☢ ", "Phase 5 — Vulnerability Scan", RED)
        urls_file = self.f("probe", "urls.txt")
        targets   = read_lines(urls_file) if os.path.exists(urls_file) else [target_url(self.target)]
        if not targets:
            targets = [target_url(self.target)]

        # nuclei
        if check_tool("nuclei"):
            vuln_out  = self.f("vulnscan", "nuclei.txt")
            jsonl_out = self.f("vulnscan", "nuclei.jsonl")
            rm_f(vuln_out)
            rm_f(jsonl_out)

            info("Updating nuclei templates...")
            run("nuclei -update-templates -silent", timeout=60)

            targets_file = self.f("vulnscan", "targets.txt")
            write_lines(targets_file, targets)
            info(f"Running nuclei against {len(targets)} target(s)...")
            # Single pass: text output + JSONL export together
            cmd = (
                f"nuclei -l {shlex.quote(targets_file)} "
                f"-severity critical,high,medium,low "
                f"-c {self.threads} "
                f"-rate-limit {self.rate} "
                f"-o {shlex.quote(vuln_out)} "
                f"-je {shlex.quote(jsonl_out)} "
                f"-silent "
                f"{self.proxy_flag()}"
            )
            self.rl(cmd, "nuclei.log", timeout=900)

            total = count_lines(vuln_out)
            ok(f"Nuclei findings: {CYAN}{BOLD}{total}{R}")
            self.state.set("vulnscan", "nuclei_count", total)

            # Parse severity from JSONL
            sev_counts: dict[str, int] = {}
            for line in read_lines(jsonl_out):
                try:
                    sev = json.loads(line).get("info", {}).get("severity", "unknown").lower()
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                except json.JSONDecodeError:
                    pass
            if not sev_counts and total:
                sev_counts["unknown"] = total
            self.state.set("vulnscan", "sev_counts", sev_counts)
            sev_table(sev_counts, "Nuclei severity breakdown")

            if total:
                print(f"  {YELLOW}{BOLD}Findings preview:{R}")
                for ln in read_lines(vuln_out)[:10]:
                    print(f"  {YELLOW}▸{R} {ln[:120]}")
                print()
        else:
            warn("nuclei not found  →  sudo apt install -y nuclei")

        # nikto — comprehensive web scan
        if check_tool("nikto"):
            nikto_out = self.f("vulnscan", "nikto.txt")
            rm_f(nikto_out)
            for u in targets[:2]:  # cap to 2 for RAM
                info(f"Running nikto on {u}...")
                cmd = (
                    f"nikto -h {shlex.quote(u)} "
                    f"-o {shlex.quote(nikto_out)} "
                    f"-Format txt "
                    f"-maxtime 300 "
                    f"-nointeractive "
                    f"{self.proxy_flag('nikto')}"
                )
                self.rl(cmd, "nikto.log", timeout=360)
            ok("nikto done")
            self.state.set("vulnscan", "nikto_file", nikto_out)
        else:
            warn("nikto not found  →  sudo apt install -y nikto")

        self.state.mark_done("vulnscan")

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 6 — XSS
    # ─────────────────────────────────────────────────────────────────────────

    def phase_xss(self) -> None:
        section("🪃", "Phase 6 — XSS Scanning", RED)
        if not check_tool("nuclei"):
            err("nuclei not found  →  sudo apt install -y nuclei")
            return

        urls_file = self.f("probe", "urls.txt")
        targets   = read_lines(urls_file) if os.path.exists(urls_file) else [target_url(self.target)]
        if not targets:
            targets = [target_url(self.target)]

        # Include parameterised URLs from crawl for better XSS coverage
        params_file = self.f("crawl", "params.txt")
        if os.path.exists(params_file):
            targets = list(dict.fromkeys(targets + read_lines(params_file)))

        targets_file = self.f("xss", "xss_targets.txt")
        write_lines(targets_file, targets[:50])  # cap for RAM

        xss_out   = self.f("xss", "nuclei_xss.txt")
        xss_jsonl = self.f("xss", "nuclei_xss.jsonl")
        rm_f(xss_out)
        rm_f(xss_jsonl)

        n_targets = min(len(targets), 50)
        info(f"Running nuclei XSS templates on {n_targets} target(s)...")
        cmd = (
            f"nuclei -l {shlex.quote(targets_file)} "
            f"-tags xss "
            f"-severity critical,high,medium,low "
            f"-c {self.threads} "
            f"-rate-limit {self.rate} "
            f"-o {shlex.quote(xss_out)} "
            f"-je {shlex.quote(xss_jsonl)} "
            f"-silent "
            f"{self.proxy_flag()}"
        )
        self.rl(cmd, "xss.log", timeout=600)

        total = count_lines(xss_out)
        ok(f"XSS findings: {CYAN}{BOLD}{total}{R}")
        self.state.set("xss", "finding_count", total)
        self.state.set("xss", "results_file", xss_out)

        if total:
            print(f"  {RED}{BOLD}XSS Findings:{R}")
            for ln in read_lines(xss_out)[:10]:
                print(f"  {RED}▸{R} {ln[:120]}")
            sev_table({"xss": total}, "XSS summary")

        self.state.mark_done("xss")

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 7 — SQLi
    # ─────────────────────────────────────────────────────────────────────────

    def phase_sqli(self) -> None:
        section("💉", "Phase 7 — SQL Injection (sqlmap)", RED)
        if not check_tool("sqlmap"):
            err("sqlmap not found  →  sudo apt install -y sqlmap")
            return

        params_file = self.f("crawl", "params.txt")
        if not os.path.exists(params_file) or count_lines(params_file) == 0:
            # Fallback: use base URL with a common parameter
            params_file = self.f("sqli", "sqlmap_targets.txt")
            write_lines(params_file, [target_url(self.target) + "/?id=1"])
            warn(
                "No params file — testing base URL only\n"
                "  Run crawl phase first for better coverage: --phase crawl"
            )

        sqli_out = self.f("sqli")
        n = count_lines(params_file)
        info(f"Testing {n} URL(s) with sqlmap...")

        cmd = (
            f"sqlmap -m {shlex.quote(params_file)} "
            f"--batch "
            f"--level=1 --risk=1 "
            f"--forms "
            f"--output-dir={shlex.quote(sqli_out)} "
            f"--random-agent "
            f"--threads={min(self.threads, 5)} "
            f"--timeout=10 "
            f"--retries=1 "
            f"{self.proxy_flag('sqlmap')}"
        )
        rc = self.rl(cmd, "sqlmap.log", timeout=900)
        if rc == -1:
            warn("sqlmap timed out — check sqli/ for partial results")

        # Count injectable endpoints from log
        injectable = 0
        log_path = self.f("logs", "sqlmap.log")
        if os.path.exists(log_path):
            for line in read_lines(log_path):
                if "is vulnerable" in line or "sqlmap identified" in line:
                    injectable += 1

        color = RED if injectable else CYAN
        ok(f"sqlmap complete — injectable points found: {color}{BOLD}{injectable}{R}")
        self.state.set("sqli", "injectable_count", injectable)
        if injectable:
            sev_table({"injectable": injectable}, "SQLi summary")
        self.state.mark_done("sqli")

    # ─────────────────────────────────────────────────────────────────────────
    # Report
    # ─────────────────────────────────────────────────────────────────────────

    def generate_report(self) -> str:
        section("📋", "Generating Report", CYAN)
        elapsed = int(time.time() - self.start_t)
        mins, secs = divmod(elapsed, 60)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")
        F  = self.state.data.get("findings", {})

        nmap_hosts = []
        nmap_json  = self.f("portscan", "summary.json")
        if os.path.exists(nmap_json):
            try:
                with open(nmap_json, encoding='utf-8') as fh:
                    nmap_hosts = json.load(fh)
            except (json.JSONDecodeError, OSError):
                pass

        sev_counts = F.get("vulnscan", {}).get("sev_counts", {})
        sev_row = " | ".join(
            f"{s.upper()}: {sev_counts.get(s, 0)}"
            for s in ("critical", "high", "medium", "low", "info")
        ) or "—"

        md = [
            f"# Red Recce Report — {self.target}",
            f"",
            f"| | |",
            f"|---|---|",
            f"| **Target** | `{self.target}` |",
            f"| **Generated** | {ts} |",
            f"| **Duration** | {mins}m {secs}s |",
            f"| **Output** | `{self.outdir}` |",
            f"",
            "---",
            "",
            "## Summary",
            "",
            "| Phase | Result |",
            "|-------|--------|",
            f"| Subdomains | {F.get('recon',{}).get('subdomain_count','—')} |",
            f"| Live hosts | {F.get('probe',{}).get('live_count','—')} |",
            f"| Open ports | {F.get('portscan',{}).get('open_port_count','—')} |",
            f"| Dir hits | {F.get('crawl',{}).get('hit_count','—')} |",
            f"| Nuclei findings | {F.get('vulnscan',{}).get('nuclei_count','—')} |",
            f"| Nuclei severity | {sev_row} |",
            f"| XSS findings | {F.get('xss',{}).get('finding_count','—')} |",
            f"| SQLi injectable | {F.get('sqli',{}).get('injectable_count','—')} |",
            "",
            "## Phases",
            "",
        ]
        for p in PHASE_ORDER:
            done = self.state.is_done(p)
            icon, name, _ = PHASE_META[p]
            md.append(f"- {'[x]' if done else '[ ]'} {icon} {name}")

        # Subdomains
        subs = read_lines(self.f("recon", "subdomains.txt"))
        if subs:
            md += ["", "## Subdomains", ""]
            md += [f"- `{s}`" for s in subs[:300]]
            if len(subs) > 300:
                md.append(f"\n_…{len(subs)-300} more in recon/subdomains.txt_")

        # Live hosts
        live = read_lines(self.f("probe", "urls.txt"))
        if live:
            md += ["", "## Live Hosts", ""]
            md += [f"- {u}" for u in live[:100]]

        # Open ports
        if nmap_hosts:
            md += ["", "## Open Ports", ""]
            for h in nmap_hosts:
                if not h["ports"]:
                    continue
                md.append(f"### {h['name'] or h['ip']}")
                md += ["", "| Port | Service | Version |", "|------|---------|---------|"]
                for p in h["ports"]:
                    ver = f"{p['product']} {p['version']}".strip() or "—"
                    md.append(f"| {p['port']}/{p['proto']} | {p['service'] or '—'} | {ver} |")
                md.append("")

        # Nuclei
        nuclei_txt = self.f("vulnscan", "nuclei.txt")
        if os.path.exists(nuclei_txt) and count_lines(nuclei_txt):
            md += ["", "## Nuclei Findings", ""]
            for ln in read_lines(nuclei_txt)[:200]:
                md.append(f"- `{ln}`")

        # Nikto
        nikto_txt = self.f("vulnscan", "nikto.txt")
        if os.path.exists(nikto_txt) and count_lines(nikto_txt):
            md += ["", "## Nikto Findings", ""]
            for ln in read_lines(nikto_txt)[:100]:
                if ln.startswith("+") or "OSVDB" in ln:
                    md.append(f"- `{ln}`")

        # Directory hits
        hits = read_lines(self.f("crawl", "hits.txt"))
        if hits:
            md += ["", "## Directory Hits", ""]
            md += [f"- `{h}`" for h in hits[:200]]

        # XSS
        xss_txt = self.f("xss", "nuclei_xss.txt")
        if os.path.exists(xss_txt) and count_lines(xss_txt):
            md += ["", "## XSS Findings", ""]
            for ln in read_lines(xss_txt)[:100]:
                md.append(f"- `{ln}`")

        # SQLi
        injectable = F.get("sqli", {}).get("injectable_count", 0)
        if injectable:
            md += [
                "", "## SQL Injection", "",
                f"sqlmap found **{injectable}** injectable parameter(s).",
                f"Full results: `{self.f('sqli')}/`",
            ]

        # File tree
        md += [
            "", "## Output Files", "",
            "```",
            f"{self.outdir}/",
            "  recon/subdomains.txt       subdomains",
            "  probe/urls.txt             live hosts",
            "  probe/httpx.jsonl          full httpx output",
            "  probe/whatweb.txt          tech fingerprint",
            "  probe/wafw00f.txt          WAF detection",
            "  portscan/nmap.*            nmap results",
            "  portscan/summary.json      parsed open ports",
            "  crawl/hits.txt             directory hits",
            "  crawl/params.txt           parameterised URLs",
            "  vulnscan/nuclei.txt        nuclei findings",
            "  vulnscan/nuclei.jsonl      nuclei JSONL (severity data)",
            "  vulnscan/nikto.txt         nikto findings",
            "  xss/nuclei_xss.txt         XSS findings",
            "  sqli/                      sqlmap results",
            "  logs/                      all tool logs",
            "  report/report.md           this file",
            "```",
        ]

        report_path = self.f("report", "report.md")
        with open(report_path, 'w', encoding='utf-8') as fh:
            fh.write('\n'.join(md) + '\n')
        ok(f"Report: {CYAN}{report_path}{R}")
        return report_path

    # ─────────────────────────────────────────────────────────────────────────
    # Run
    # ─────────────────────────────────────────────────────────────────────────

    def run(self, phases: list[str]) -> None:
        banner()
        dry_tag = f"  {YELLOW}[DRY-RUN — no commands will execute]{R}" if self.dry_run else ""
        hdr(
            f"Target: {CYAN}{self.target}{R}  |  {GRAY}{self.outdir}{R}"
            + (f"\n{dry_tag}" if dry_tag else "")
        )

        self.check_tools(phases[0] if len(phases) == 1 else "all")
        print()

        if self.args.burp_help:
            self._print_proxy_guidance()
            return

        done = self.state.data.get("completed", [])
        if done and self.args.resume:
            info(f"Resuming — completed: {', '.join(done)}")
        elif done and not self.args.resume:
            warn("Previous run found. Use --resume to skip completed phases.")

        dispatch = {
            "recon":    self.phase_recon,
            "probe":    self.phase_probe,
            "portscan": self.phase_portscan,
            "crawl":    self.phase_crawl,
            "vulnscan": self.phase_vulnscan,
            "xss":      self.phase_xss,
            "sqli":     self.phase_sqli,
        }

        for phase in phases:
            _, name, _ = PHASE_META[phase]
            if self.args.resume and self.state.is_done(phase):
                info(f"Skipping {name} (done)")
                continue
            try:
                dispatch[phase]()
            except KeyboardInterrupt:
                warn(f"\nInterrupted during {name}. Rerun with --resume.")
                break
            except Exception as e:
                err(f"Error in {name}: {e}")
                import traceback; traceback.print_exc()
                continue

        self.generate_report()

        elapsed = int(time.time() - self.start_t)
        mins, secs = divmod(elapsed, 60)
        F = self.state.data.get("findings", {})
        hdr(f"Done  ·  {mins}m {secs}s  ·  {self.outdir}")
        print(
            f"  {GREEN}▸{R} Subdomains:   {YELLOW}{F.get('recon',{}).get('subdomain_count','—')}{R}\n"
            f"  {GREEN}▸{R} Live hosts:   {YELLOW}{F.get('probe',{}).get('live_count','—')}{R}\n"
            f"  {GREEN}▸{R} Open ports:   {YELLOW}{F.get('portscan',{}).get('open_port_count','—')}{R}\n"
            f"  {GREEN}▸{R} Dir hits:     {YELLOW}{F.get('crawl',{}).get('hit_count','—')}{R}\n"
            f"  {GREEN}▸{R} Nuclei hits:  {RED}{F.get('vulnscan',{}).get('nuclei_count','—')}{R}\n"
            f"  {GREEN}▸{R} XSS found:    {RED}{F.get('xss',{}).get('finding_count','—')}{R}\n"
            f"  {GREEN}▸{R} SQLi found:   {RED}{F.get('sqli',{}).get('injectable_count','—')}{R}\n"
        )

    def _print_proxy_guidance(self) -> None:
        section("🔀", "Proxy Setup (Burp / ZAP)")
        print(f"""
  {YELLOW}Burp Community (8080):{R}
    python3 redrecce.py -t {self.target} --proxy http://127.0.0.1:8080

  {YELLOW}OWASP ZAP (8090):{R}
    python3 huntkit.py -t {self.target} --proxy http://127.0.0.1:8090

  {GRAY}Start ZAP headless:{R}
    zaproxy -daemon -host 127.0.0.1 -port 8090 -config api.disablekey=true &
""")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Red Recce — Kali Linux Live USB Bug Bounty Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-t", "--target", default=None,
        help="Target: domain, IP, or host:port (e.g. localhost:3000)")
    parser.add_argument("--phase", default="all",
        choices=PHASE_ORDER + ["all"],
        help="Phase to run (default: all)")
    parser.add_argument("-o", "--output", default="./redrecce_output",
        help="Output directory (default: ./redrecce_output)")
    parser.add_argument("--rate", type=int, default=50,
        help="Request rate limit (default: 50 — safe for live USB)")
    parser.add_argument("--threads", type=int, default=10,
        help="Thread count (default: 10 — safe for live USB)")
    parser.add_argument("--proxy", default=None,
        help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--wordlist", default=None,
        help="Wordlist for gobuster/ffuf (auto-detects seclists)")
    parser.add_argument("--scope", default=None,
        help="Scope file — one domain per line")
    parser.add_argument("--resume", action="store_true",
        help="Skip already-completed phases")
    parser.add_argument("--dry-run", action="store_true",
        help="Print commands without running them")
    parser.add_argument("--burp-help", action="store_true",
        help="Show proxy setup guidance")
    parser.add_argument("--check-tools", action="store_true",
        help="Check which tools are installed then exit")
    parser.add_argument("--list-phases", action="store_true",
        help="List phases and tools then exit")

    args = parser.parse_args()

    if args.list_phases or args.check_tools:
        banner()
        print(f"  {RED}{BOLD}Phases & tools:{R}\n")
        for pid in PHASE_ORDER:
            icon, name, tools = PHASE_META[pid]
            parts = []
            for t in tools:
                c = GREEN if check_tool(t) else RED
                parts.append(f"{c}{t}{R}")
            print(f"  {icon}  {CYAN}{pid:<10}{R} {name:<30} {', '.join(parts)}")
        print()
        print(f"  {CYAN}Install all missing tools:{R}")
        print(
            f"  sudo apt install -y nmap sqlmap ffuf nikto gobuster nuclei "
            f"subfinder httpx-toolkit whatweb wafw00f dnsrecon\n"
        )
        sys.exit(0)

    if not args.target:
        parser.error("-t/--target is required")

    try:
        args.target = validate_target(args.target)
    except ValueError as e:
        err(str(e))
        sys.exit(1)

    if args.proxy and not re.match(r'^https?://', args.proxy, re.IGNORECASE):
        err(f"Invalid proxy '{args.proxy}' — expected http://host:port")
        sys.exit(1)

    if not 1 <= args.threads <= 200:
        err("--threads must be 1–200")
        sys.exit(1)
    if not 1 <= args.rate <= 5000:
        err("--rate must be 1–5000")
        sys.exit(1)

    phases = PHASE_ORDER if args.phase == "all" else [args.phase]

    def _sigint(sig, frame):
        print(f"\n\n{YELLOW}  Interrupted — rerun with --resume{R}\n")
        sys.exit(0)
    signal.signal(signal.SIGINT, _sigint)

    try:
        kit = HuntKit(args)
    except ValueError as e:
        err(str(e))
        sys.exit(1)
    except OSError as e:
        err(f"Cannot create output dir: {e}")
        sys.exit(1)

    kit.run(phases)


if __name__ == "__main__":
    main()
