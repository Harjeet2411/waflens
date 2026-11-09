"""Generate examples/sample-audit.log: synthetic ModSecurity v3 JSON audit records.

The traffic mixes a real-looking SQLi/XSS scan from two IPs with a noisy
rule tripping on a legitimate search endpoint, so every report section has
something to show. Seeded, so the output is reproducible.
"""

import json
import random
import sys
from datetime import datetime, timedelta

RULES = {
    "942100": ("SQL Injection Attack Detected via libinjection", ["attack-sqli"]),
    "941100": ("XSS Attack Detected via libinjection", ["attack-xss"]),
    "930120": ("OS File Access Attempt", ["attack-lfi"]),
    "932160": ("Remote Command Execution: Unix Shell Code Found", ["attack-rce"]),
    "920350": ("Host header is a numeric IP address", ["attack-protocol"]),
    "942430": ("Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12)", ["attack-sqli"]),
}
SCANNERS = ["203.0.113.66", "198.51.100.23"]
SCAN_URIS = [
    ("/products?id=1' OR '1'='1", "942100"),
    ("/search?q=<script>alert(1)</script>", "941100"),
    ("/download?file=../../../../etc/passwd", "930120"),
    ("/cgi-bin/status?cmd=;cat /etc/shadow", "932160"),
]


def record(rng, ts, ip, method, uri, status, rule_ids):
    messages = []
    for rid in rule_ids:
        msg, tags = RULES[rid]
        messages.append({
            "message": msg,
            "details": {
                "ruleId": rid,
                "severity": "2",
                "ver": "OWASP_CRS/4.0.0",
                "tags": ["application-multi", "language-multi", *tags, "OWASP_CRS"],
            },
        })
    if status == 403:
        messages.append({
            "message": "Inbound Anomaly Score Exceeded (Total Score: 10)",
            "details": {"ruleId": "949110", "severity": "0", "tags": ["anomaly-evaluation"]},
        })
    return {
        "transaction": {
            "client_ip": ip,
            "time_stamp": ts.strftime("%a %b %d %H:%M:%S %Y"),
            "unique_id": f"{rng.getrandbits(64):016x}",
            "request": {"method": method, "http_version": 1.1, "uri": uri},
            "response": {"http_code": status},
            "messages": messages,
        }
    }


def main(out):
    rng = random.Random(2411)
    start = datetime(2026, 10, 18, 9, 0, 0)
    lines = []
    for i in range(240):
        ts = start + timedelta(seconds=i * 45 + rng.randint(0, 40))
        roll = rng.random()
        if roll < 0.45:
            ip = rng.choice(SCANNERS)
            uri, rid = rng.choice(SCAN_URIS)
            lines.append(record(rng, ts, ip, "GET", uri, 403, [rid]))
        elif roll < 0.85:
            # Shoppers searching for "c++ & c# books" etc. trip the special-char rule.
            ip = f"192.0.2.{rng.randint(10, 60)}"
            q = rng.choice(["c%2B%2B+%26+c%23+books", "50%25+off+%22deals%22", "rock+%26+roll+%28live%29"])
            lines.append(record(rng, ts, ip, "GET", f"/search?q={q}", 200, ["942430"]))
        else:
            ip = f"100.64.{rng.randint(0, 3)}.{rng.randint(1, 250)}"
            lines.append(record(rng, ts, ip, "GET", "/", 200, ["920350"]))
    for rec in lines:
        out.write(json.dumps(rec) + "\n")
    out.write("this line is not json and should be skipped\n")


if __name__ == "__main__":
    main(sys.stdout)
