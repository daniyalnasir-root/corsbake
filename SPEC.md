name: corsbake
purpose: Probe a target endpoint for CORS misconfigurations that allow credentialed cross-origin reads, and bake a working `poc.html` the user hosts on their attacker domain to demonstrate the data theft to the program owner.
actionable_payoff: Writes `poc.html` to disk for every probe that resolves to VULNERABLE — the file fetches the target with `credentials: include`, shows the leaked response in the browser, and POSTs it back to a configurable webhook. Final block prints the literal `python3 -m http.server` and `http://attacker/poc.html` commands. The user runs three commands and has a screenshot.
language: python
why_language: stdlib `urllib`+`http.server` cover preflight + actual request; HTML emission is one f-string; no third-party dep needed.
features:
- Six probe families: exact-origin reflection, null origin, wildcard+credentials, scheme downgrade, suffix bypass, subdomain wildcard
- Honors a victim cookie/auth header so the cross-origin response is the *authenticated* one
- Emits `poc.html` per vulnerable probe (overwrites with the strongest hit; or `--all` for one file per hit)
- Final artifact panel prints serve + open commands ready to copy
- `--no-poc` for dry probing in CI
- Colored-narrative output: section rules with ══════, ▣/▢/✗ verdict glyphs, no tables
input_contract: --url (target) + --attacker-origin + optional --cookie / --header for victim auth
output_contract: per-probe narrative blocks with verdicts, then an artifact section pointing at the written PoC and the next 2 commands to run
output_style: colored-narrative — section rules with `══════`, verdict glyphs `▣`/`▢`/`✗`, key-value indented blocks. No tables, no `---` divider, no box-drawing borders, no log-tree `▷`. Distinct from email-atom/curl2nuclei/paramsneak.
safe_test_target: httpbin.org/response-headers (synthesizes any ACAO/ACAC headers) for vulnerable demo; httpbin.org/headers for safe demo
synonym_names:
- corscraft
- cors-poc
- corsmint
source_inspiration_url: https://portswigger.net/web-security/cors
