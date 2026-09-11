# PQC Posture Scan

Find quantum-vulnerable cryptography in your repository before an auditor does.

Scans a repository for quantum-vulnerable cryptographic usage and reports what a CNSA 2.0 or NIST PQC migration would have to replace. Detects RSA and classical elliptic-curve key generation, hardcoded curve and modulus parameters, certificate and key files, TLS configuration pinned to pre-quantum cipher suites, and dependency manifests that pull in cryptographic libraries. Emits a posture report as a job summary, a machine-readable JSON artifact, and optional SARIF for code scanning.

## Inputs

| Input | Description | Required | Default |
| --- | --- | --- | --- |
| path | Root directory to scan, relative to the workspace. | No | `.` |
| fail-on | Severity that fails the job. One of none, low, medium, high, critical. | No | `high` |
| report-format | Output format for the report artifact. One of json, sarif, both. | No | `json` |
| report-path | File path for the written report artifact. | No | `pqc-posture-report.json` |
| exclude | Newline-separated glob patterns to exclude from the scan, in addition to .git and common vendor directories. | No | `` |

## Outputs

| Output | Description |
| --- | --- |
| findings-count | Total number of quantum-vulnerable findings. |
| highest-severity | Highest severity observed, or none when the scan is clean. |
| report-path | Path to the written report artifact. |

## Pull request usage

```yaml
name: pqc-posture-scan-pull-request
on:
  pull_request:
permissions:
  contents: read
jobs:
  pqc-posture-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: pqc-posture-scan
        uses: sanctumsecopsmssp/action-pqc-posture-scan@v1
        with:
          path: '.'
          fail-on: 'high'
          report-format: 'json'
          report-path: 'pqc-posture-report.json'
          exclude: ''
```

## Scheduled usage

```yaml
name: pqc-posture-scan-scheduled
on:
  schedule:
    - cron: '17 3 * * 1'
permissions:
  contents: read
jobs:
  pqc-posture-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: pqc-posture-scan
        uses: sanctumsecopsmssp/action-pqc-posture-scan@v1
        with:
          path: '.'
          fail-on: 'high'
          report-format: 'json'
          report-path: 'pqc-posture-report.json'
          exclude: ''
```

## Consume outputs

```yaml
jobs:
  consume:
    runs-on: ubuntu-latest
    steps:
      - id: pqc-posture-scan
        uses: sanctumsecopsmssp/action-pqc-posture-scan@v1
      - run: echo "findings-count=${{ steps.pqc-posture-scan.outputs.findings-count }}"
      - run: echo "highest-severity=${{ steps.pqc-posture-scan.outputs.highest-severity }}"
      - run: echo "report-path=${{ steps.pqc-posture-scan.outputs.report-path }}"
```

## License

Apache-2.0. See [LICENSE](LICENSE).

---

Sanctum SecOps LLC · [Website](https://sanctumsecops.com) · [Support](https://sanctumsecops.com/support) · [Contact](mailto:Brian@sso-labs.com)
