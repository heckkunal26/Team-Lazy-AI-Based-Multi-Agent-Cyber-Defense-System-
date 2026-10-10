# INC-9: R2L

- Source: flows · Events: 3 · IPs: n/a (flow data)
- Severity 65/100 · Confidence 0.61
- MITRE ATT&CK: T1110/T1078 Credential Access / Valid Accounts
- Status: acknowledged · Time to contain: 265.1s
- Playbook: Enforce MFA; reset exposed credentials; review remote logins

## Evidence (why it fired)
- root_shell avg 0.33 vs normal 0.00 (z=7.4)
- dst_host_srv_diff_host_rate avg 0.26 vs normal 0.03 (z=3.4)
- num_access_files avg 0.33 vs normal 0.01 (z=2.4)
- top services: ftp_data×2, http×1

## Actions
- none

## Timeline
- 14:46:32 Detect: R2L from flows (3 events)
- 14:46:32 Analyse: MITRE T1110/T1078 Credential Access / Valid Accounts, severity 65
- 14:46:32 Respond: no source IP in flow data; playbook recommended, awaiting analyst
- 14:46:32 Intel: TinyFish Search+Fetch found 1 sources
- 14:50:46 Analyst acknowledged; playbook applied manually
- 14:50:47 Report: incident report written (NIST 800-61 structure)
