# Phishing Indicator Detection

## Description
Detects clicks on known malicious URLs captured via Microsoft Defender 
Safe Links, indicating a user may have interacted with a phishing email.

## MITRE ATT&CK
- Tactic: Initial Access
- Technique: T1566.002 — Phishing: Spearphishing Link

## Severity
Medium

## KQL Query
```kql
UrlClickEvents
| where TimeGenerated > ago(24h)
| where ActionType == "ClickBlocked" or ActionType == "ClickAllowed"
| where ThreatTypes has "Phish"
| project TimeGenerated, AccountUpn, Url, ActionType,
          IPAddress, NetworkMessageId
| order by TimeGenerated desc
```

## Why This Fires
A user clicked a URL flagged as phishing by Defender Safe Links —
either blocked or allowed through depending on policy configuration.

## False Positives
- Security awareness training simulation emails (e.g. Hoxhunt)
- Miscategorized marketing emails with redirect URLs

## Tuning Notes
- Exclude known simulation sender domains (e.g. your Hoxhunt domain)
- Focus on ActionType == "ClickAllowed" first — these are highest risk
- Correlate with EmailEvents to see the original sender

## Response Actions
1. Check if ActionType was ClickAllowed — if yes, treat as incident
2. Pull the original email via NetworkMessageId
3. Search for same URL clicked by other users in the org
4. Isolate user's device if credential harvesting site confirmed
