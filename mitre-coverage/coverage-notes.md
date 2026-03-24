# MITRE ATT&CK Coverage

## Techniques Covered

| Tactic | Technique ID | Technique Name | Detection Rule |
|--------|-------------|----------------|----------------|
| Initial Access | T1078.004 | Valid Accounts: Cloud Accounts | [Impossible Travel](../detections/impossible-travel.md) |
| Credential Access | T1110.001 | Brute Force: Password Guessing | [AAD Brute Force](../detections/brute-force-aad.md) |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | [Phishing Indicators](../detections/phishing-indicators.md) |

## Coverage Gaps (Planned)

| Tactic | Technique ID | Technique Name | Priority |
|--------|-------------|----------------|----------|
| Persistence | T1098.001 | Account Manipulation: AAD | High |
| Defense Evasion | T1562.001 | Disable Security Tools | High |
| Exfiltration | T1567.002 | Exfiltration to Cloud Storage | Medium |

## Environment Context
These rules are written for a Microsoft Sentinel environment with:
- Azure Entra ID sign-in logs
- Microsoft Defender for Office 365 (Safe Links)
- CrowdStrike Falcon EDR

## Notes
Coverage gaps are intentional next priorities for this detection library.
