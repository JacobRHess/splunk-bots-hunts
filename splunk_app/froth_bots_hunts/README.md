# froth_bots_hunts

Generated Splunk app for the splunk-bots-hunts portfolio. Do not edit by hand: regenerate with `uv run python harness/build_splunk_app.py`.

## Install

Copy `froth_bots_hunts/` to `$SPLUNK_HOME/etc/apps/` and restart Splunk, or upload the folder as an app package via Manage Apps.

## Contents

- 9 scheduled detections (`default/savedsearches.conf`), each ATT&CK-annotated and configured as an Enterprise Security correlation search with notable + risk actions.
- 8 dashboards (`default/data/ui/views/`):
- `overview`
- `investigation`
- `aws-recon-bstoll`
- `bstoll-l-endpoint`
- `bstoll-coinhive-cryptojacking`
- `fyodor-powershell-empire`
- `azure-ad-signin-anomaly`
- `o365-cloud-account-abuse`
- CIM mapping: `eventtypes.conf` + `tags.conf` tag each BOTS v3 sourcetype into the Authentication, Network Resolution, Endpoint, and Change data models.
- Search macros (`macros.conf`): `frothly_index`, `rfc1918(1)`, `cryptomining_pools`, `frothly_users`.
- Context lookups (`lookups/`): `identities.csv` (employee/admin/service roles) and `assets.csv` (host owner + criticality), defined in `transforms.conf`.
