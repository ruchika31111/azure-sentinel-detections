# AAD Brute Force Detection

## Description
Detects a high volume of failed sign-in attempts against Azure Active Directory
accounts, indicating a password spraying or brute force attack in progress.

## MITRE ATT&CK
- Tactic: Credential Access
- Technique: T1110.001 — Brute Force: Password Guessing

## Severity
High

## KQL Query
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize FailedAttempts = count(),
            DistinctIPs = dcount(IPAddress),
            DistinctApps = dcount(AppDisplayName)
    by UserPrincipalName, bin(TimeGenerated, 10m)
| where FailedAttempts >= 10
| order by FailedAttempts desc
```

## Why This Fires
10 or more failed logins within a 10-minute window for the same account —
consistent with automated brute force or password spray tools.

## False Positives
- Misconfigured service accounts with expired credentials
- Users repeatedly mistyping passwords after a password reset
- Legacy auth clients that don't support MFA prompts

## Tuning Notes
- Raise threshold to 20+ for noisy environments
- Add filter for ResultType == 50126 (invalid credentials specifically)
- Correlate with successful login shortly after to confirm compromise

## Response Actions
1. Lock the account immediately
2. Check if any successful login followed the failures
3. Review sign-in location and device of any successful attempt
4. Notify user and reset credentials
