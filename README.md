# Log Analysis Cheatsheet

A quick-reference for the Windows Event IDs and log patterns I check most often during alert triage and threat hunting — built from real SOC analyst work, not a copy-paste of Microsoft's docs.

## Windows Security Event IDs — Most Used

| Event ID | Meaning | Why It Matters |
|----------|---------|------------------|
| 4624 | Successful logon | Baseline for normal access; correlate with 4625 for brute-force detection |
| 4625 | Failed logon | Spike = brute force; check `Logon_Type` field for attack vector (3=network, 10=RDP) |
| 4672 | Special privileges assigned | Flags privileged session start — should map to known admin activity |
| 4688 | Process creation | Core for detecting malicious process execution (needs command-line auditing enabled) |
| 4720 | User account created | Should always match a change ticket — unexpected = red flag |
| 4728 / 4732 | Member added to security-enabled group | Privilege escalation indicator |
| 4104 | PowerShell script block logging | Captures actual script content — critical for catching obfuscated attacks |

## Log Analysis Workflow

1. **Establish baseline first.** You can't spot an anomaly if you don't know what "normal" volume/pattern looks like for that log source.
2. **Pivot on the outlier, not the alert.** An alert tells you where to start — the investigation is tracing the account/host/process across other log sources.
3. **Timeline everything.** Build a simple timestamp-ordered sequence of events across sources (auth logs, process logs, network logs) — this is usually what turns "suspicious" into "confirmed."
4. **Check for log gaps.** Missing logs during a suspected incident window is itself a finding (possible log clearing — Event ID 1102).

## My Log-Analysis Automation Tool
I built a small automation tool to speed up this exact workflow — parsing raw logs into a normalized timeline format so steps 2-3 above take minutes instead of manual grep/filter work. See [`10-SOC-Automation-Scripts`](../10-SOC-Automation-Scripts) for the approach.

## Useful Filters (Splunk-style, adapt to your platform)
```spl
# Find log clearing events (possible cover-up)
index=security EventCode=1102

# Failed logons grouped by source
index=security EventCode=4625 | stats count by src_ip | sort -count
```
