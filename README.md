# PolicyGuard AI
[![PolicyGuard CI](https://github.com/AmrAbd-Elaziz/policyguard-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/AmrAbd-Elaziz/policyguard-ai/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Tests](https://img.shields.io/badge/tests-47%20passed-brightgreen)
![Security](https://img.shields.io/badge/security-gitleaks%20clean-brightgreen)
![Status](https://img.shields.io/badge/status-V1%20active-orange)
![License](https://img.shields.io/badge/license-TBD-lightgrey)

> **Firewall Security Policy Analysis, Risk Prioritization, and Control Mapping Engine**

PolicyGuard AI is a security engineering tool designed to analyze firewall rulebases, identify risky policy configurations, prioritize remediation, and map security findings to recognized cybersecurity control frameworks.

The project uses a **deterministic security analysis engine** rather than relying on AI-generated security decisions. Firewall policies are normalized, evaluated against YAML-based detection rules, scored using contextual risk factors, and transformed into actionable findings and security assessment reports.

All firewall policies, network identifiers, IP addresses, hostnames, and assessment data included in this repository are **synthetic and created specifically for demonstration and testing**.

---

## Why PolicyGuard AI?

Firewall security reviews often require engineers to manually identify issues such as:

- Overly broad source or destination access
- Unrestricted services and ports
- Insecure protocols
- Missing security logging
- Missing security inspection profiles
- Test-to-production exposure
- Broadly exposed administrative services
- Database exposure
- Missing business justification
- Complex firewall rules that should be separated

PolicyGuard converts these review patterns into reusable detection logic that can be tested, version-controlled, and consistently applied across firewall policy datasets.

---

## Architecture

```text
                 Firewall Policy
                       |
                       v
              +------------------+
              | Vendor Parser /  |
              | Normalizer       |
              +------------------+
                       |
                       v
              +------------------+
              | Normalized Rules |
              +------------------+
                       |
              +--------+---------+
              |                  |
              v                  v
      +---------------+   +---------------+
      | YAML Detection|   | Contextual    |
      | Rule Engine   |   | Risk Engine   |
      +---------------+   +---------------+
              |                  |
              +--------+---------+
                       |
                       v
              +------------------+
              | Security Findings|
              +------------------+
                       |
              +--------+---------+
              |                  |
              v                  v
      +---------------+   +---------------+
      | Control       |   | Prioritized   |
      | Mapping       |   | Remediation   |
      +---------------+   +---------------+
              |                  |
              +--------+---------+
                       |
                       v
              +------------------+
              | JSON / HTML      |
              | Security Report  |
              +------------------+
```

---

## Current Capabilities

PolicyGuard AI V1 currently provides:

- Normalized CSV firewall policy ingestion
- Normalized JSON firewall policy ingestion
- Palo Alto-style CSV parsing
- Native FortiGate firewall policy configuration parsing
- YAML-driven security detection rules
- Nested `all` and `any` detection logic
- Threshold-based `count` conditions
- Contextual firewall rule risk scoring
- Remediation priority classification
- Security control mapping
- JSON security assessment reports
- HTML security assessment reports
- Rule-pack validation
- Detection DSL validation
- Automated regression testing

---

## Detection Coverage

The current PolicyGuard rule pack contains **12 firewall security detections**:

| ID | Detection | Severity |
|---|---|---|
| PG-001 | `ANY_ANY_RULE` | Critical |
| PG-002 | `BROAD_DESTINATION` | High |
| PG-003 | `INSECURE_PROTOCOL` | High |
| PG-004 | `LOGGING_GAP` | Medium |
| PG-005 | `MISSING_SECURITY_PROFILE` | High |
| PG-006 | `MISSING_BUSINESS_JUSTIFICATION` | Medium |
| PG-007 | `TEST_PROD_MIXING` | High |
| PG-008 | `ANY_SERVICE` | High |
| PG-009 | `BROAD_SOURCE` | High |
| PG-010 | `ADMIN_SERVICE_EXPOSURE` | High |
| PG-011 | `DB_EXPOSURE` | High |
| PG-012 | `RULE_NEEDS_SPLITTING` | Medium |

Detection logic is maintained separately from the Python analysis engine in:

```text
rules/firewall_rules.yaml
```

This design allows security detections to evolve without embedding individual firewall checks directly into the application code.

---

## Detection Engine

PolicyGuard uses a YAML-based detection DSL.

A simple detection can be expressed as:

```yaml
- id: PG-003
  name: INSECURE_PROTOCOL
  severity: HIGH
  description: Insecure clear-text protocol is permitted.
  recommendation: Use an encrypted alternative or document an approved exception.
  conditions:
    action:
      equals: allow
    service:
      in:
        - telnet
        - ftp
```

More complex detections support nested logic using:

- `all`
- `any`
- `count`
- `equals`
- `not_equals`
- `in`
- `not_in`
- `empty`

For example, PolicyGuard can detect a rule that contains multiple broad access conditions using a threshold-based `count` expression.

---

## Risk Prioritization

Detection severity and rule-level risk are intentionally treated as separate concepts.

A firewall rule may contain several findings while also receiving a contextual risk score based on factors such as:

- Broad source access
- Broad destination access
- Unrestricted services
- Administrative service exposure
- Insecure protocols
- Database exposure
- Test/production mixing
- Missing security inspection
- Missing logging
- Missing business justification

Rules are assigned a risk score from **0 to 100** and a remediation priority:

| Risk Score | Priority |
|---|---|
| 80–100 | P1 |
| 60–79 | P2 |
| 35–59 | P3 |
| 1–34 | P4 |
| 0 | P5 |

The scoring model is a transparent project-specific heuristic designed for prioritization. It should not be interpreted as an industry-standard risk methodology.

---

## Security Control Mapping

PolicyGuard can associate findings with contextual references from security frameworks and security engineering principles.

Current mapping categories include:

- Security engineering principles
- NIST Cybersecurity Framework 2.0
- CIS Controls
- PCI DSS references

Control mappings are **contextual security references only** and do not constitute a compliance determination.

Mappings are maintained in:

```text
rules/control_mappings.yaml
```

---

## Supported Input Formats

### Normalized CSV

```csv
rule_id,source,destination,service,action,logging,security_profile,business_justification,environment
R001,any,any,any,allow,no,no,,production
```

### Normalized JSON

```json
{
  "rules": [
    {
      "rule_id": "J001",
      "source": "any",
      "destination": "any",
      "service": "any",
      "action": "allow",
      "logging": "no",
      "security_profile": "no",
      "business_justification": "",
      "environment": "production"
    }
  ]
}
```

### Palo Alto-style CSV

PolicyGuard also includes a Palo Alto-style CSV parser that converts vendor-specific fields into the normalized PolicyGuard schema.

### FortiGate Configuration

PolicyGuard supports FortiGate `config firewall policy` configuration blocks and normalizes vendor-specific policy fields into the PolicyGuard analysis schema.

Supported FortiGate policy attributes include addresses, services, actions, logging, comments, interfaces, and common security profile references.

```text
config firewall policy
    edit 1
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set logtraffic disable
    next
end
```

---

## Usage

Analyze the normalized sample policy:

```bash
python app.py data/sample_rules.csv
```

Analyze the Palo Alto-style sample policy:

```bash
python app.py data/paloalto_sample.csv --vendor paloalto
```
Analyze a FortiGate firewall configuration:

```bash
python app.py data/fortigate_sample.conf --vendor fortigate
```
Generated reports are written to the `reports/` directory.

---
## Example Finding

A high-risk firewall rule can generate findings similar to:

```text
Rule ID: R001
Risk Score: 100
Priority: P1

Findings:
- ANY_ANY_RULE
- BROAD_SOURCE
- BROAD_DESTINATION
- ANY_SERVICE
- LOGGING_GAP
- MISSING_SECURITY_PROFILE
- MISSING_BUSINESS_JUSTIFICATION
```

Each finding includes:

- Detection identifier
- Severity
- Description
- Recommended remediation
- Applicable security control references

---

## Report Output

PolicyGuard generates both machine-readable and human-readable assessment results:

```text
reports/
├── normalized-policyguard-report.json
├── normalized-policyguard-report.html
├── paloalto-policyguard-report.json
└── paloalto-policyguard-report.html
```

The HTML assessment report includes:

- Executive summary
- Assessment scope
- Assessment methodology
- Finding statistics
- Prioritized remediation plan
- Highest-risk firewall rules
- Detailed security findings
- Framework coverage references

---


## Testing

Run the complete test suite with:

```bash
pytest -q
```

The project currently includes tests covering:

- Firewall detection behavior
- YAML detection rules
- Nested detection logic
- Threshold-based conditions
- Palo Alto parsing
- FortiGate configuration parsing and normalization
- FortiGate parser edge cases
- Risk behavior
- Control mappings
- Reporting
- Rule-pack validation
- Detection DSL validation

---

## Security and Data Sanitization

This repository is designed for public demonstration.

All sample firewall policies, IP addresses, network names, hostnames, and assessment data are synthetic.

Documentation-only IPv4 ranges are used where appropriate, including:

- `192.0.2.0/24`
- `198.51.100.0/24`
- `203.0.113.0/24`

No production firewall configurations, customer information, credentials, internal domains, or proprietary rulebases are included in this repository.

---

## Project Status

**PolicyGuard AI V1.1 — Active Development**

The deterministic firewall analysis engine is functional and includes normalized CSV/JSON ingestion, Palo Alto-style CSV parsing, native FortiGate policy parsing, YAML-driven detection, contextual risk prioritization, control mapping, reporting, rule validation, and automated tests.

The AI-assisted explanation layer is planned for a future release and is intentionally separated from deterministic security detection.

---

## Roadmap

Planned capabilities include:

- Native Palo Alto export parsing
- Additional firewall vendor support
- Custom detection rule packs
- Web-based analysis interface
- Hugging Face demonstration environment
- AI-assisted finding explanations
- Expanded framework mappings
- Enhanced report visualization

---

## Disclaimer

PolicyGuard AI is a security engineering and assessment tool.

Findings, risk scores, recommendations, and framework mappings require professional review and should not be treated as automatic compliance determinations or substitutes for organization-specific risk assessment.
