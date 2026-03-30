# Red Recce

**Red Recce** is a bug bounty orchestrator built for Kali Linux live USB environments.
`apt`-only tooling, low RAM defaults, sequential phase execution.

```
╔══════════════════════════════════════════════════════════╗
║  Red Recce — Kali Live USB Edition                       ║
║  nmap · sqlmap · ffuf · nuclei · nikto · gobuster        ║
║  subfinder · httpx · whatweb · wafw00f · dnsrecon        ║
╚══════════════════════════════════════════════════════════╝
```

---

## Install dependencies

```bash
sudo apt install -y nmap sqlmap ffuf nikto gobuster nuclei \
  subfinder httpx-toolkit whatweb wafw00f dnsrecon curl seclists
```

---

## Quick start

```bash
# Full scan — all phases
python3 redrecce.py -t target.com

# OWASP Juice Shop (localhost)
python3 redrecce.py -t localhost:3000

# Single phase
python3 redrecce.py -t target.com --phase recon

# Resume a previous run
python3 redrecce.py -t target.com --resume

# Route through Burp Suite
python3 redrecce.py -t target.com --proxy http://127.0.0.1:8080

# Dry-run — print commands without executing
python3 redrecce.py -t target.com --dry-run

# Check which tools are installed
python3 redrecce.py --check-tools
```

---

## Phases

| Phase | Tools | Description |
|-------|-------|-------------|
| `recon` | dnsrecon, subfinder | DNS records + subdomain enumeration |
| `probe` | httpx-toolkit, whatweb, wafw00f | Live host detection, tech fingerprint, WAF check |
| `portscan` | nmap | Port + service version scan |
| `crawl` | gobuster, ffuf | Directory brute-force, parameter URL harvest |
| `vulnscan` | nuclei, nikto | Vulnerability template scanning |
| `xss` | nuclei | XSS-tagged nuclei templates |
| `sqli` | sqlmap | SQL injection testing |

---

## Options

```
-t / --target       Target host or host:port  (required)
--phase             One phase or "all"  (default: all)
-o / --output       Output directory  (default: ./redrecce_output)
--rate              Requests/sec  (default: 50)
--threads           Thread count  (default: 10)
--proxy             HTTP proxy  (e.g. http://127.0.0.1:8080)
--wordlist          Custom wordlist for gobuster/ffuf
--resume            Skip already-completed phases
--dry-run           Print commands without running them
--burp-help         Show Burp/ZAP proxy setup guidance
--check-tools       Check installed tools and exit
--list-phases       List phases and their tools then exit
```

---

## Output structure

```
redrecce_output/<target>/
  recon/subdomains.txt       discovered subdomains
  probe/urls.txt             live hosts
  probe/httpx.jsonl          full httpx JSON output
  probe/whatweb.txt          technology fingerprint
  probe/wafw00f.txt          WAF detection results
  portscan/nmap.*            nmap results (all formats)
  portscan/summary.json      parsed open ports
  crawl/hits.txt             directory hits
  crawl/params.txt           parameterised URLs for XSS/SQLi
  vulnscan/nuclei.txt        nuclei findings
  vulnscan/nuclei.jsonl      nuclei JSONL (severity data)
  vulnscan/nikto.txt         nikto findings
  xss/nuclei_xss.txt         XSS findings
  sqli/                      sqlmap output directory
  logs/                      raw tool logs
  report/report.md           markdown report
```

---

## Notes

- Defaults (`--threads 10`, `--rate 50`) are intentionally conservative for live USB RAM constraints.
- All tools are installed via `apt` — no Go, no compilation, no internet required beyond the initial install.
- State is persisted in `.redrecce_state.json` inside the output folder; use `--resume` to continue interrupted scans.
- Loopback targets (`localhost`, `127.0.0.1`) automatically skip DNS/subdomain phases.

---

## License

MIT — see [LICENSE](LICENSE).
