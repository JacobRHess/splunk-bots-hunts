# 05 — Azure AD sign-in anomalies

## The thread

Frothly is a Colorado and California company, so its Azure AD sign-in logs should sit almost entirely in US and Canadian geo-IP space. They mostly do, except for a block of sign-ins from Hong Kong. Twenty-seven successful sign-ins resolve to `HK`, every one of them from a single hosting IP, `104.207.83.63`. Two employee accounts are involved: `bgist@froth.ly` and `fyodor@froth.ly`.

`fyodor@froth.ly` is the same identity behind the PowerShell implant on `FYODOR-L` in [scenario 04](../04-fyodor-powershell-empire/). Seeing that account authenticate to the cloud from a Hong Kong VPS is the cloud-side echo of the endpoint compromise: the attacker is reusing Fyodor's credentials against Azure AD, not just his laptop.

Alongside the successful foreign logins there are ten failed sign-ins spread across five accounts from the same source, which reads as credential testing rather than one fat-fingered password.

## How I worked it

1. Counted successful `ms:aad:signin` events by `location.country`. US and CA dominate; `HK` is the one country that has no business being there.
2. Pulled the source IP for those non-US/CA sign-ins. All of them trace to `104.207.83.63`, a hosting-provider address, not a residential or corporate range.
3. Counted the distinct accounts that logged in successfully from Hong Kong: two, `bgist` and `fyodor`. The `fyodor` overlap with scenario 04 is the pivot that ties cloud to endpoint.
4. Counted the failed sign-ins. Ten failures across five accounts from the same IP, consistent with a spray against known usernames.

## Reading the results

The geo-IP outlier is the cheapest signal here. A brewery's workforce does not log in from a Hong Kong data-center IP, so country-plus-hosting-ASN alone is enough to surface this without tuning. The reused `fyodor` account is the part that matters: the same credentials show up on a compromised endpoint and in foreign cloud sign-ins, so this is one actor operating across both surfaces, not two unrelated oddities.

The failures change the read from "one stolen credential" to "the attacker is working a list." Five accounts tested, two of them landing successful sessions, points at a spray or a credential dump rather than a single phish.

## Hunts

| # | File | Question | Answer |
|---|---|---|---|
| 1 | `hunts/01-foreign-signin-country.spl` | Which country outside North America did successful sign-ins come from? | `HK` |
| 2 | `hunts/02-foreign-signin-ip.spl` | What source IP did the foreign sign-ins originate from? | `104.207.83.63` |
| 3 | `hunts/03-foreign-signin-accounts.spl` | How many distinct accounts signed in successfully from Hong Kong? | `2` |
| 4 | `hunts/04-failed-signins.spl` | How many failed Azure AD sign-ins are in the logs? | `10` |

## ATT&CK mapping

| Technique | Where it shows up |
|---|---|
| T1078.004 Valid Accounts: Cloud Accounts | `bgist` and `fyodor` sign in to Azure AD from a Hong Kong hosting IP |
| T1110.003 Password Spraying | Ten failed sign-ins across five accounts from the same source |

## What I would have detected

A rule for `ms:aad:signin loginStatus=Success` where `location.country` is outside an allow-list of expected countries would have fired on the first Hong Kong sign-in. Pairing it with a second rule that watches for failed sign-ins fanning across multiple accounts from one IP catches the spray that preceded the successful logins. Both ship with this scenario as saved searches in the Splunk app.
