# Impossible Travel Detection

## Description
Detects sign-ins from two geographically distant locations within a 
timeframe that makes physical travel impossible — a strong indicator 
of credential compromise or account takeover.

## MITRE ATT&CK
- Tactic: Initial Access
- Technique: T1078.004 — Valid Accounts: Cloud Accounts

## Severity
High

## KQL Query
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          LocationDetails, AppDisplayName
| sort by UserPrincipalName, TimeGenerated asc
| extend PrevTime = prev(TimeGenerated),
         PrevLocation = prev(Location),
         PrevUser = prev(UserPrincipalName)
| where UserPrincipalName == PrevUser
| extend TimeDiffHours = datetime_diff('hour', TimeGenerated, PrevTime)
| where TimeDiffHours < 2 and Location != PrevLocation
| project UserPrincipalName, PrevLocation, Location,
          TimeDiffHours, TimeGenerated
```

## Why This Fires
Two successful logins from different countries within 2 hours —
physically impossible without a plane.

## False Positives
- VPN users switching exit nodes
- Executives traveling with legitimate rapid location changes
- Shared accounts

## Tuning Notes
- Whitelist known VPN IP ranges
- Adjust the 2-hour window based on your org's geography
- Correlate with MFA failure events for higher confidence

## Response Actions
1. Disable account temporarily
2. Revoke all active sessions in Entra ID
3. Force MFA re-registration
4. Check for mailbox rules and OAuth app grants
