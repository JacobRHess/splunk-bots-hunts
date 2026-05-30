# 06 — O365 cloud account abuse

## The thread

Scenario 05 flagged two Frothly accounts signing in to Azure AD from a Hong Kong VPS, `bgist` and `fyodor`. This scenario follows what those two accounts did once they were inside Office 365. The Office 365 management-activity log records both halves of it. `bgist@froth.ly` creates an anonymous sharing link to a file called `BRUCE BIRTHDAY HAPPY HOUR PICS.lnk`, and the link is created from `104.207.83.63`, the same Hong Kong hosting IP from scenario 05. A Windows shortcut named like a batch of party photos is not a party photo, it is a lure, and once the link is anonymous anyone with the URL can pull it. Six external IPs do.

`fyodor@froth.ly` shows up on the administrative side. Fyodor is a regular mailbox user, not an Exchange admin, yet the log has `fyodor` running `Set-Mailbox` against two other people's mailboxes: `klagerfield`, where it resets the refresh-token validity window, and `bgist`, where it sets `AccountDisabled` to true. The same identity that ran the PowerShell implant in scenario 04 is now reconfiguring colleagues' cloud mailboxes, disabling one of them outright.

## How I worked it

1. Counted `ms:o365:management` events by `Operation` to see the shape of the activity. `AnonymousLinkUsed`, `AnonymousLinkCreated`, `SharingSet`, and `Set-Mailbox` stand out against an otherwise routine stream of file access and sign-ins.
2. Pulled the file behind the anonymous link. One file, `BRUCE BIRTHDAY HAPPY HOUR PICS.lnk`, is the only thing shared this way.
3. Found who created the link and from where. `bgist@froth.ly` created it from `104.207.83.63`, which ties this straight back to the Hong Kong VPS in scenario 05.
4. Counted the distinct external IPs that retrieved the shared file under the `anonymous` principal. Six of them pulled the `.lnk`.
5. Listed the accounts running `Set-Mailbox`. Filtering to Frothly mailbox users leaves `fyodor@froth.ly`, modifying `bgist` and `klagerfield`. A Microsoft service account also touches a mailbox, which is expected and filtered out.

## Reading the results

The anonymous-link operations are the high-signal pair. A Colorado and California brewery has little reason to publish internal OneDrive files to anonymous URLs, and a shared `.lnk` named after photos is a lure rather than a document. The fact that the link was created from the same Hong Kong IP that scenario 05 already flagged removes any doubt about who created it: this is the attacker operating Frothly's own OneDrive to stage a payload.

The `Set-Mailbox` runs change the read from "stolen credentials used to sign in" to "stolen credentials used to administer the tenant." Fyodor is not an admin, so a Frothly mailbox user reconfiguring other mailboxes is account takeover in progress. Disabling `bgist` while `bgist` is the account that just shared the lure looks like the attacker cleaning up behind one identity using another.

## Hunts

| # | File | Question | Answer |
|---|---|---|---|
| 1 | `hunts/01-anonymous-link-file.spl` | Which file was retrieved through an anonymous sharing link in Office 365? | `BRUCE BIRTHDAY HAPPY HOUR PICS.lnk` |
| 2 | `hunts/02-anonymous-link-creator.spl` | Which Frothly account created the anonymous sharing link? | `bgist@froth.ly` |
| 3 | `hunts/03-anonymous-link-source-ip.spl` | What source IP was the anonymous link created from? | `104.207.83.63` |
| 4 | `hunts/04-anonymous-link-retrievals.spl` | How many distinct external IPs retrieved the anonymously shared file? | `6` |
| 5 | `hunts/05-set-mailbox-abuse.spl` | Which Frothly account ran Set-Mailbox against other users' mailboxes? | `fyodor@froth.ly` |

## ATT&CK mapping

| Technique | Where it shows up |
|---|---|
| T1078.004 Valid Accounts: Cloud Accounts | `bgist` and `fyodor` drive the O365 activity from the same Hong Kong VPS flagged in scenario 05 |
| T1080 Taint Shared Content | The `BRUCE BIRTHDAY HAPPY HOUR PICS.lnk` lure is staged on OneDrive and exposed by an anonymous sharing link |
| T1098 Account Manipulation | `fyodor` runs `Set-Mailbox` against `klagerfield`, resetting the refresh-token validity window |
| T1531 Account Access Removal | `fyodor` runs `Set-Mailbox` against `bgist` with `AccountDisabled` set to true |

## What I would have detected

Two saved searches ship with this scenario. The first fires when any Frothly user creates an anonymous sharing link, which surfaces the `bgist` link and the file behind it with no tuning, because anonymous external links are rare and worth a look every time. The second fires when a regular mailbox user, not an admin or a Microsoft service account, runs `Set-Mailbox`, which catches `fyodor` reconfiguring other people's mailboxes. Both ship as correlation searches in the Splunk app.
