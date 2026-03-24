# azure-sentinel-detections
KQL detection rules for Microsoft Sentinel — mapped to MITRE ATT&amp;CK
# Azure Sentinel Detection Rules

KQL-based detection rules for Microsoft Sentinel, mapped to MITRE ATT&CK.
Built from real-world incident response experience in a healthcare Azure environment.

## Detections

| Rule | MITRE Technique | Severity |
|------|----------------|----------|
| [Impossible Travel](./detections/impossible-travel.md) | T1078.004 – Cloud Accounts | High |
| [AAD Brute Force](./detections/brute-force-aad.md) | T1110.001 – Password Guessing | High |
| [Phishing Indicators](./detections/phishing-indicators.md) | T1566 – Phishing | Medium |

## Environment
- SIEM: Microsoft Sentinel
- Identity: Azure Entra ID
- EDR: CrowdStrike Falcon
- CSPM: Wiz

## Author
Ruchika | Security Engineer | [LinkedIn]linkedin.com/in/ruchika-mittal-b02143136 
