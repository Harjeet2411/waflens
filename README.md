# waflens

Point it at a ModSecurity or Coraza JSON audit log and get a one-screen answer to
"what is my WAF actually blocking, and which rules are just noise?"

```
$ waflens examples/sample-audit.log --top 5
Events: 240   Blocked: 106 (44.2%)

Top rules
  942430 Restricted SQL Character Anomaly Detection (args     101  ████████████████████████
  920350 Host header is a numeric IP address                   33  ████████
  941100 XSS Attack Detected via libinjection                  29  ███████
  942100 SQL Injection Attack Detected via libinjection        29  ███████
  932160 Remote Command Execution: Unix Shell Code Found       26  ██████

Attack types
  sqli         130  ████████████████████████
  protocol      33  ██████
  xss           29  █████
  rce           26  █████
  lfi           22  ████

Top client IPs
  203.0.113.66       55  ████████████████████████
  198.51.100.23      51  ██████████████████████
  192.0.2.31          5  ██
  192.0.2.18          4  ██
  192.0.2.43          4  ██

Top paths
  /search             130  ████████████████████████
  /                    33  ██████
  /products            29  █████
  /cgi-bin/status      26  █████
  /download            22  ████

Possible false positives (one rule, one path, many clients)
  rule 942430 on /search: 101 hits from 43 IPs
  rule 920350 on /: 33 hits from 32 IPs
```

## Why

A fresh OWASP CRS deployment usually produces thousands of audit entries a day.
Most of the work in running a WAF is tuning: separating real attacks from rules
that misfire on legitimate traffic. waflens does the first pass:

- **Top rules, attack types, client IPs and paths**, with CRS bookkeeping rules
  (949110, 980130 and friends) left out so they don't drown the signal.
- **Possible false positives**: a single rule firing on a single path for many
  unrelated clients is usually real users tripping a generic signature, not an
  attack. In the sample above, rule 942430 fires on `/search` for 43 different
  shoppers, while the actual SQLi/XSS scan comes from two IPs.
- **Text, Markdown or JSON output**, so the same report works in a terminal, a
  PR comment or a pipeline.

## Install

```
pip install git+https://github.com/Harjeet2411/waflens
```

No dependencies beyond the Python 3.9+ standard library.

## Usage

```
waflens /var/log/modsec_audit.log                 # text report
waflens audit-*.log -f markdown > report.md       # several files, Markdown
kubectl logs deploy/ingress | waflens -f json -    # stdin, JSON for further processing
waflens audit.log --fp-min-ips 20 --top 20        # stricter false-positive threshold
```

waflens reads the JSON-lines audit format (`SecAuditLogFormat JSON` in
ModSecurity v3, the default JSON format in Coraza). Malformed lines are skipped
and counted on stderr. A request counts as blocked when the WAF answered 403,
406 or 429.

## Development

```
python -m unittest discover -s tests -v
python tools/make_sample.py > examples/sample-audit.log   # regenerate the synthetic sample
```

The sample log is synthetic (seeded, reproducible) and uses documentation IP
ranges, so it is safe to publish.

## Roadmap

- Native ModSecurity v2 serial/concurrent audit log format
- Suggest `SecRuleUpdateTargetById` exclusions for false-positive candidates
- HTML report with an hourly timeline

## License

MIT
