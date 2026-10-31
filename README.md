# Detection Engineering Lab

Detections and tooling I write to practice and show how I approach detection engineering. Each rule is mapped to MITRE ATT&CK, explains why it exists and lists known false positives and how to tune them.

None of this comes from client or employer environments. Thresholds are starting points, so tune them to your own baseline.

## Detections

| Rule | ATT&CK | KQL (Sentinel) | SPL (Splunk) |
|---|---|---|---|
| Password spray against Entra ID | T1110.003 | [kql](detections/kql/password_spray_entra.kql) | [spl](detections/spl/password_spray.spl) |
| Encoded PowerShell execution | T1059.001 | [kql](detections/kql/encoded_powershell.kql) | [spl](detections/spl/encoded_powershell.spl) |
| New inbox rule forwarding mail externally | T1114.003 | [kql](detections/kql/inbox_forwarding_rule.kql) | |
| LSASS memory access by an unusual process | T1003.001 | [kql](detections/kql/lsass_access.kql) | [spl](detections/spl/lsass_access.spl) |
| Impossible travel between Entra ID sign-ins | T1078 | [kql](detections/kql/impossible_travel_entra.kql) | |

## How I write a detection

1. **Start from behavior, not an IOC.** What does the attacker have to do that a normal user rarely does?
2. **Know the telemetry.** Confirm which table or sourcetype records the behavior and which fields can be trusted.
3. **Baseline before alerting.** Run the query over 14 to 30 days and look at what fires before choosing a threshold.
4. **Enrich at query time.** Add the context an analyst needs, such as user, host, geo and counts, so triage starts with the answer.
5. **Write down the false positives.** Every rule lists the benign activity it catches and how to exclude it safely.
6. **Test it.** Reproduce the behavior in a lab, for example with Atomic Red Team, and confirm the rule fires.

## Tools

### `tools/ioc_enrich.py`

Classifies a list of IOCs as IPv4, domain, URL or hash, deduplicates them and can optionally enrich IPs through the AbuseIPDB API. It outputs JSON or CSV for a ticket or SOAR playbook.

```bash
pip install requests
python tools/ioc_enrich.py iocs.txt --format csv
ABUSEIPDB_API_KEY=yourkey python tools/ioc_enrich.py iocs.txt --enrich
```

Run the tests with:

```bash
python -m unittest discover tests
```
