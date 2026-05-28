# 02 — BSTOLL-L endpoint logon profile

## Why this hunt

[Scenario 01](../01-aws-recon-bstoll/) established that the IAM user `bstoll` was compromised and used to enumerate AWS on 2018-08-20 from a residential AT&T IP without MFA. The natural next question: did the laptop `BSTOLL-L` itself get popped, or were the AWS credentials stolen by some other vector?

This scenario answers that by pulling BSTOLL-L's `WinEventLog:Security` apart and asking four questions that, together, rule out (or rule in) endpoint compromise as the pivot point.

## How I worked it

1. Confirmed BSTOLL-L is the noisy one: it has roughly 5x more Windows Security events than the next-loudest Frothly host. If the laptop was attacker-touched, the signal should be in here.
2. Characterized the logon profile by `Logon_Type`. The dominant value is `5` (service logon), which is normal-and-boring system activity. Interactive logons (`Type=2`) are bounded.
3. Looked specifically for remote logons (`Type=3` network, `Type=10` RemoteInteractive) from external `Source_Network_Address` values. Found none.
4. Counted the interactive (`Type=2`) logons, which is the upper bound on hands-on-keyboard sessions during the BOTSv3 capture window.

## Reading the results

The endpoint shows a *normal* logon profile: lots of services, four interactive logins, zero remote sessions from outside private RFC1918 space. There is no 4624 evidence of attacker login to BSTOLL-L itself. That doesn't rule out a credential stealer running under bstoll's own session (which would not generate a new logon), but it does rule out the easy answers (RDP brute force, pass-the-hash from another box, stolen domain creds used remotely).

The likely AWS-credential-theft vector is therefore one of:
- Browser session cookie theft for `console.aws.amazon.com`
- Local read of `~/.aws/credentials` by a process running as `bstoll`
- Phishing the access keys directly out of bstoll without ever touching the laptop

A follow-up scenario can dig into the file-access and network telemetry to chase those.

## Hunts

| # | File | Question | Answer |
|---|---|---|---|
| 1 | `hunts/01-most-active-host.spl` | Which host has the highest WinEventLog:Security event volume? | `BSTOLL-L` |
| 2 | `hunts/02-dominant-logon-type.spl` | What is the dominant `Logon_Type` on BSTOLL-L's 4624 events? | `5` |
| 3 | `hunts/03-external-source-ips.spl` | How many distinct *external* source IPs appear in BSTOLL-L's 4624 events? | `0` |
| 4 | `hunts/04-interactive-logons.spl` | How many interactive (`Type=2`) logons happened on BSTOLL-L? | `4` |

## ATT&CK hunted for (and not found)

| Technique | Sub-technique | Where I looked | Result |
|---|---|---|---|
| T1021 Remote Services | T1021.001 RDP | `Logon_Type=10` 4624 events | none |
| T1021 Remote Services | T1021.002 SMB/Admin Shares | `Logon_Type=3` 4624 events from external IPs | none |
| T1078 Valid Accounts | T1078.002 Domain Accounts | 4624 events with non-local source | none |
