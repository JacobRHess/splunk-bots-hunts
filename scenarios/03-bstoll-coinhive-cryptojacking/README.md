# 03 — BSTOLL-L browser cryptojacking (Coinhive)

## Why this hunt

[Scenario 02](../02-bstoll-l-endpoint/) ruled out the easy endpoint-compromise answers for `BSTOLL-L`: no remote logons, no external 4624 source IPs, a normal service-logon profile. The leftover hypotheses all ran through the browser or a local process under `bstoll`'s own session. So I went looking at what `BSTOLL-L` was actually talking to on the wire.

The DNS told the story immediately. On 2018-08-20, `BSTOLL-L` (`192.168.247.131`) resolved `coinhive.com` and a fan of `ws*.coinhive.com` subdomains. Coinhive is the in-browser Monero miner that defined the 2017-2018 cryptojacking wave. The `ws*` hosts are its mining-pool websocket nodes. This is a browser that loaded a page (or an ad) carrying the Coinhive miner JavaScript, then opened long-lived websocket sessions to the pool to hash on the visitor's CPU.

## How I worked it

1. Pivoted off scenario 02's conclusion (browser or local process) into network telemetry. `stream:dns` is the cheapest place to catch an in-browser miner, because the miner has to resolve its pool nodes before it can hash.
2. Searched `stream:dns` for any `coinhive.com` resolution and grouped by `src_ip`. One internal workstation stood out: `192.168.247.131`. The other source, `192.168.247.2`, is the internal resolver recursing the same lookups, not a second victim.
3. Counted the distinct coinhive FQDNs that workstation resolved. Six in total: the apex `coinhive.com` plus five `ws*` mining nodes.
4. Pulled the `src_mac` to nail the asset identity independent of DHCP lease churn: `00:0C:29:B8:44:5E`. That MAC is `BSTOLL-L`, the same laptop scenario 01 and 02 were built around.

## Reading the results

The five `ws*.coinhive.com` resolutions are the signal that matters. A single hit on the apex domain could be an analyst reading about Coinhive. Five distinct mining-node lookups in one window is an active session: the miner rotating across pool nodes to keep hashing. The resolved addresses sit in OVH space (`37.187.0.0/16`, `217.182.164.14`), which is where Coinhive ran its websocket infrastructure.

This closes the scenario 02 loop. `BSTOLL-L`'s browser was executing attacker-controlled JavaScript. That is the same surface that makes the leading AWS-credential-theft theory (console session-cookie theft) plausible: a browser already running untrusted code is a browser that can have its cookies and local storage read. The cryptojacking is not proof of the AWS theft, but it puts a compromised browser on the exact host the stolen `bstoll` keys trace back to.

## Hunts

| # | File | Question | Answer |
|---|---|---|---|
| 1 | `hunts/01-coinhive-internal-host.spl` | Which internal host resolved coinhive.com mining domains? | `192.168.247.131` |
| 2 | `hunts/02-coinhive-fqdns.spl` | How many distinct `coinhive.com` FQDNs did the host resolve? | `6` |
| 3 | `hunts/03-mining-endpoints.spl` | How many distinct mining websocket endpoints (`ws*.coinhive.com`) were resolved? | `5` |
| 4 | `hunts/04-infected-host-mac.spl` | What is the MAC of the host running the in-browser miner? | `00:0C:29:B8:44:5E` |

## ATT&CK mapping

| Technique | Where it shows up |
|---|---|
| T1496 Resource Hijacking | In-browser Monero miner hashing on `BSTOLL-L`'s CPU |
| T1059.007 JavaScript | Coinhive miner runs as page JavaScript, no binary on disk |
| T1071.001 Web Protocols | Long-lived websocket sessions to `ws*.coinhive.com` pool nodes |
| T1189 Drive-by Compromise | Miner delivered through web content / ad loaded in the browser |

## What I would have detected

A DNS-side rule for `query=*coinhive.com OR query=*.minexmr.com OR query=*.nanopool.org` (a small known-mining-pool list) would have fired on the first `ws*` resolution, with near-zero false positives in a brewery's traffic. Cryptojacking is loud in DNS precisely because the miner cannot start without resolving its pool. That is the cheapest detection Frothly was missing on the endpoint side, and it sits on the same host the AWS compromise traces to.
