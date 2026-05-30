# froth_bots_hunts

Generated Splunk app for the splunk-bots-hunts portfolio. Do not edit by hand: regenerate with `uv run python harness/build_splunk_app.py`.

## Install

Copy `froth_bots_hunts/` to `$SPLUNK_HOME/etc/apps/` and restart Splunk, or upload the folder as an app package via Manage Apps.

## Contents

- 9 scheduled detections (`default/savedsearches.conf`), each ATT&CK-annotated.
- 7 dashboards (`default/data/ui/views/`):
- `overview`
- `aws-recon-bstoll`
- `bstoll-l-endpoint`
- `bstoll-coinhive-cryptojacking`
- `fyodor-powershell-empire`
- `azure-ad-signin-anomaly`
- `o365-cloud-account-abuse`
