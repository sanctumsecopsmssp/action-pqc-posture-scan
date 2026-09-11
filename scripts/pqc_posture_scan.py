#!/usr/bin/env python3
"""Repository scanner for pre-quantum cryptographic posture findings."""
import argparse
import fnmatch
import json
import os
import re
import sys
from pathlib import Path

SEVERITIES = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SKIP_DIRECTORIES = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor", "dist", "build", "__pycache__"}
RULES = (
    ("PQC001", "high", "RSA key generation or usage", re.compile(r"\b(RSA_generate_key|RSA_new|rsa\.generate_private_key|RSA\s*\(|\brsa\b)", re.IGNORECASE)),
    ("PQC002", "high", "Classical elliptic-curve cryptography", re.compile(r"\b(EC_KEY|ECDSA|secp(?:256r1|384r1|521r1)|prime256v1|ed25519|x25519)\b", re.IGNORECASE)),
    ("PQC003", "medium", "Pre-quantum TLS cipher suite", re.compile(r"\b(TLS_RSA|ECDHE_(?:RSA|ECDSA)|AES(?:128|256)-(?:GCM|CBC)-SHA)\b", re.IGNORECASE)),
    ("PQC004", "low", "Cryptographic key or certificate file", re.compile(r"-----BEGIN (?:RSA |EC |)?(?:PRIVATE KEY|CERTIFICATE)-----")),
    ("PQC005", "low", "Cryptographic dependency", re.compile(r"\b(openssl|cryptography|pycryptodome|bouncycastle|node-forge|crypto-js)\b", re.IGNORECASE)),
)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Find quantum-vulnerable cryptography in a repository.")
    parser.add_argument("--path", default=".")
    parser.add_argument("--fail-on", default="high", choices=tuple(SEVERITIES))
    parser.add_argument("--report-format", default="json", choices=("json", "sarif", "both"))
    parser.add_argument("--report-path", default="pqc-posture-report.json")
    parser.add_argument("--exclude", default="")
    return parser.parse_args()


def output_path(raw_path, root):
    path = Path(raw_path)
    return path if path.is_absolute() else root / path


def write_github_output(values):
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        return
    with open(output_file, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def write_summary(markdown):
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as handle:
            handle.write(markdown + "\n")


def excluded(relative_path, patterns):
    text = relative_path.as_posix()
    return any(fnmatch.fnmatch(text, pattern) for pattern in patterns)


def scan(root, patterns):
    findings = []
    for current_root, directories, filenames in os.walk(root):
        directories[:] = [name for name in directories if name not in SKIP_DIRECTORIES]
        for filename in filenames:
            file_path = Path(current_root) / filename
            relative = file_path.relative_to(root)
            if excluded(relative, patterns) or file_path.stat().st_size > 2_000_000:
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for rule_id, severity, message, expression in RULES:
                for match in expression.finditer(content):
                    line = content.count("\n", 0, match.start()) + 1
                    findings.append({
                        "rule_id": rule_id,
                        "severity": severity,
                        "message": message,
                        "path": relative.as_posix(),
                        "line": line,
                        "match": match.group(0),
                    })
    return findings


def sarif_report(findings):
    rules = []
    known = set()
    for rule_id, severity, message, _ in RULES:
        if rule_id not in known:
            rules.append({"id": rule_id, "shortDescription": {"text": message}, "defaultConfiguration": {"level": "error" if severity in {"high", "critical"} else "warning"}})
            known.add(rule_id)
    results = []
    for finding in findings:
        results.append({
            "ruleId": finding["rule_id"],
            "level": "error" if finding["severity"] in {"high", "critical"} else "warning",
            "message": {"text": finding["message"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding["path"]}, "region": {"startLine": finding["line"]}}}],
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "PQC Posture Scan", "rules": rules}}, "results": results}]}


def write_report(report_path, report_format, report):
    report_path.parent.mkdir(parents=True, exist_ok=True)
    if report_format == "sarif":
        report_path.write_text(json.dumps(sarif_report(report["findings"]), indent=2) + "\n", encoding="utf-8")
        return report_path
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if report_format == "both":
        sarif_path = report_path.with_suffix(".sarif")
        sarif_path.write_text(json.dumps(sarif_report(report["findings"]), indent=2) + "\n", encoding="utf-8")
    return report_path


def main():
    args = parse_arguments()
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"error: scan path is not a directory: {root}", file=sys.stderr)
        return 2
    patterns = [line.strip() for line in args.exclude.splitlines() if line.strip()]
    try:
        findings = scan(root, patterns)
        highest = max((item["severity"] for item in findings), key=lambda value: SEVERITIES[value], default="none")
        report = {"schema_version": "1.0", "scan_root": str(root), "findings": findings, "summary": {"findings_count": len(findings), "highest_severity": highest}}
        report_path = write_report(output_path(args.report_path, root), args.report_format, report)
    except OSError as exc:
        print(f"error: unable to write posture report: {exc}", file=sys.stderr)
        return 3
    summary = "\n".join(["## PQC Posture Scan", "", f"- Findings: **{len(findings)}**", f"- Highest severity: **{highest}**", f"- Report: `{report_path}`"])
    write_github_output({"findings-count": len(findings), "highest-severity": highest, "report-path": report_path})
    write_summary(summary)
    print(summary)
    return 1 if SEVERITIES[highest] >= SEVERITIES[args.fail_on] and args.fail_on != "none" else 0


if __name__ == "__main__":
    sys.exit(main())
