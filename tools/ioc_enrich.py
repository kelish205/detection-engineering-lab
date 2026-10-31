"""Classify, deduplicate and optionally enrich a list of IOCs.

Reads one indicator per line, handles common defanging such as hxxp and [.],
classifies each as ipv4, domain, url, md5, sha1 or sha256 and writes JSON or CSV.
With --enrich, public IPv4 addresses are checked against AbuseIPDB using the
ABUSEIPDB_API_KEY environment variable.
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import sys

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def refang(value):
    value = value.strip()
    value = re.sub(r"^hxxp", "http", value, flags=re.I)
    return value.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def classify(value):
    if re.fullmatch(r"[a-f0-9]+", value, re.I) and len(value) in HASH_LENGTHS:
        return HASH_LENGTHS[len(value)]
    try:
        ipaddress.IPv4Address(value)
        return "ipv4"
    except ValueError:
        pass
    if re.match(r"^https?://", value, re.I):
        return "url"
    if DOMAIN_RE.match(value):
        return "domain"
    return "unknown"


def parse(lines):
    seen = set()
    results = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        value = refang(line)
        ioc_type = classify(value)
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        record = {"ioc": value, "type": ioc_type}
        if ioc_type == "ipv4":
            record["private"] = ipaddress.IPv4Address(value).is_private
        results.append(record)
    return results


def enrich_ip(ip, api_key, session):
    response = session.get(
        ABUSEIPDB_URL,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=10,
    )
    response.raise_for_status()
    data = response.json().get("data", {})
    return {
        "abuse_score": data.get("abuseConfidenceScore"),
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "total_reports": data.get("totalReports"),
    }


def enrich(records):
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        sys.exit("Set ABUSEIPDB_API_KEY to use --enrich")
    import requests

    with requests.Session() as session:
        for record in records:
            if record["type"] == "ipv4" and not record["private"]:
                try:
                    record.update(enrich_ip(record["ioc"], api_key, session))
                except requests.RequestException as err:
                    record["error"] = str(err)
    return records


def write(records, fmt, out):
    if fmt == "json":
        json.dump(records, out, indent=2)
        out.write("\n")
        return
    fields = []
    for record in records:
        for field in record:
            if field not in fields:
                fields.append(field)
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    writer.writerows(records)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("file", help="file with one IOC per line, or - for stdin")
    parser.add_argument("--format", choices=["json", "csv"], default="json")
    parser.add_argument("--enrich", action="store_true", help="enrich public IPs with AbuseIPDB")
    args = parser.parse_args(argv)

    if args.file == "-":
        lines = sys.stdin.readlines()
    else:
        with open(args.file, encoding="utf-8") as handle:
            lines = handle.readlines()

    records = parse(lines)
    if args.enrich:
        records = enrich(records)
    write(records, args.format, sys.stdout)


if __name__ == "__main__":
    main()
