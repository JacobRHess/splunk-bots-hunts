# 01 — AWS reconnaissance via compromised IAM user `bstoll`

## The thread

On 2018-08-20, CloudTrail records 615 AWS API calls attributed to the IAM user `bstoll` originating mostly from `107.77.212.175` (an AT&T Mobility IP outside Frothly's normal range). The activity is broad rather than targeted: 64 distinct API actions across S3, EC2, IAM, and ELB, in a window of a few hours. Four of those calls are `ConsoleLogin` events, none of which used MFA.

That shape (broad read-only enumeration, no MFA, residential source IP, IAM-user identity) is the textbook signature of an attacker exploring a freshly compromised AWS account before deciding what to escalate against.

## How I worked it

1. Looked at `aws:cloudtrail` top users overall. `splunk_access` dominated counts (benign agent), but `bstoll` and `web_admin` stood out for the *shape* of their calls.
2. Filtered `bstoll` down to external source IPs and got `107.77.212.175` as the dominant one. AT&T Mobility ASN — not infrastructure I'd expect for a brewery employee.
3. Looked at `bstoll` ConsoleLogin events specifically. All four logged `MFAUsed=No`. Strongly suggests stolen long-term access keys / password rather than a session-hijack.
4. Counted distinct S3 buckets touched by `bstoll`. 16 buckets in one session, including `frothlyinvestigations` — the bucket name itself is a giveaway that the actor was hunting for sensitive content.

## ATT&CK mapping

| Technique | Where it shows up |
|---|---|
| T1078.004 Valid Accounts: Cloud Accounts | `bstoll` ConsoleLogin from external IP, MFA absent |
| T1580 Cloud Infrastructure Discovery | `Describe*` across EC2, ELB, security groups |
| T1619 Cloud Storage Object Discovery | `GetBucketAcl` / `GetBucketPolicy` across 16 buckets |
| T1087.004 Account Discovery: Cloud Account | `ListInstanceProfiles`, `ListAccessKeys` |

## Hunts

| # | File | Question | Answer |
|---|---|---|---|
| 1 | `hunts/01-mfa-less-console-login.spl` | Which IAM user logged into the AWS Console without MFA? | `bstoll` |
| 2 | `hunts/02-bstoll-primary-source-ip.spl` | What external IP did `bstoll`'s session originate from? | `107.77.212.175` |
| 3 | `hunts/03-bstoll-mfa-status.spl` | What MFA status was recorded on `bstoll`'s Console logins? | `No` |
| 4 | `hunts/04-buckets-enumerated.spl` | How many distinct S3 buckets did `bstoll` enumerate? | `16` |

## What I would have detected

A baseline detection rule for `eventName=ConsoleLogin AND additionalEventData.MFAUsed=No AND userIdentity.type=IAMUser` would have fired on the first of the four logins, before any S3 enumeration started. That is the cheapest, highest-signal alert Frothly was missing.
