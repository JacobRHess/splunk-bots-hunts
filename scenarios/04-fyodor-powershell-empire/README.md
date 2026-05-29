# 04 — FYODOR-L PowerShell implant (Empire-style)

## The thread

`FYODOR-L.froth.ly` is the loudest Sysmon host in the dataset, and the noise is a live PowerShell implant. The host runs `powershell.exe -NonI -W hidden -c "IEX (...FromBase64String((gp HKLM:\Software\Microsoft\Network debug).debug)))"`. That one line carries the whole technique: read a base64 blob out of a registry value, decode it in memory, and run it with `IEX`. Nothing touches disk, so file-hash and AV signatures never get a look.

The same command runs under two identities. Once as `AzureAD\FyodorMalteskesko` (the logged-in user), and once as `NT AUTHORITY\SYSTEM` with a parent of `svchost.exe -k netsvcs -p -s Schedule`. That parent is the Task Scheduler service, so a scheduled task relaunches the implant as SYSTEM on its own cadence. The user-context copies are spawned by hidden-window `powershell.exe -enc <base64>` launchers, the shape PowerShell Empire uses for its stage-1 agent.

I scoped this scenario to FYODOR-L's Sysmon process telemetry (`EventCode=1`, process create). The initial-access stager is a separate question and lives in different telemetry (PowerShell ScriptBlock logging on another host), so I left it out rather than stretch this hunt across sourcetypes.

## How I worked it

1. Filtered Sysmon `EventCode=1` (process create) command lines for `FromBase64String`. Every hit is on `FYODOR-L`, all hidden-window in-memory decoders. That is the implant executing.
2. Extracted the registry path the decoder reads from: `HKLM:\Software\Microsoft\Network`, value `debug`. The payload lives in the registry, which is why nothing shows up as a dropped file.
3. Split the executing identities. The SYSTEM copy is parented by `svchost.exe ... -s Schedule`, which names the persistence: a scheduled task under the `Schedule` service. The other copy runs as `FyodorMalteskesko`, the hands-on user session.

## Reading the results

This is a fileless foothold. The detection surface is not a binary or a hash. It is the command line: a hidden-window PowerShell that pipes `FromBase64String` into `IEX`, and a SYSTEM PowerShell whose parent is the Task Scheduler rather than a console or a logon shell. Both are rare enough in a brewery's process telemetry to alert on directly.

`FYODOR-L` is a different host from the `BSTOLL-L` thread in scenarios 01-03, so this is a second compromised endpoint, not a continuation of the same one. Frothly had at least two separate footholds running concurrently on 2018-08-20: a browser-resident cryptominer on `BSTOLL-L` and a PowerShell implant on `FYODOR-L`.

## Hunts

| # | File | Question | Answer |
|---|---|---|---|
| 1 | `hunts/01-encoded-ps-host.spl` | Which host ran in-memory PowerShell that decodes a base64 payload? | `FYODOR-L.froth.ly` |
| 2 | `hunts/02-registry-payload-path.spl` | Which registry path stored the encoded implant? | `HKLM:\Software\Microsoft\Network` |
| 3 | `hunts/03-scheduled-task-persistence.spl` | Which Windows service relaunched the SYSTEM copy of the implant? | `Schedule` |
| 4 | `hunts/04-implant-user.spl` | Which non-SYSTEM user account executed the implant? | `AzureAD\FyodorMalteskesko` |

## ATT&CK mapping

| Technique | Where it shows up |
|---|---|
| T1059.001 PowerShell | The implant runs entirely as `powershell.exe` command lines |
| T1027 Obfuscated Files or Information | Base64 payload in the registry, `-enc` launchers |
| T1053.005 Scheduled Task | SYSTEM copy parented by `svchost.exe ... -s Schedule` |
| T1112 Modify Registry | Payload stored in and read from `HKLM:\Software\Microsoft\Network` |

## What I would have detected

A rule on `EventCode=1 Image=*\powershell.exe` whose command line matches `FromBase64String` or `-enc `, plus a second rule for `powershell.exe` parented by `svchost.exe`, would have caught both the execution and the persistence on the first run. Encoded in-memory PowerShell and Scheduler-parented PowerShell are both high-signal and almost never legitimate on a workstation. `FYODOR-L` produced both, repeatedly.
