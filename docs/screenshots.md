# Capturing dashboard screenshots

The dashboards render in Splunk, so the screenshots in the README are captured
by hand from a local instance. Steps to reproduce them.

## 1. Boot Splunk and load data

```powershell
docker compose -f docker/compose.yml up -d
```

For the richest dashboards, install the full BOTSv3 dataset (index `botsv3`)
from <https://github.com/splunk/botsv3>. The dashboard panels query `index=*`,
so the committed fixtures also populate them if you only run:

```powershell
uv run python harness/ingest_fixtures.py
```

## 2. Install the generated app

```powershell
docker cp splunk_app/froth_bots_hunts splunk-bots:/opt/splunk/etc/apps/froth_bots_hunts
docker exec splunk-bots /opt/splunk/bin/splunk restart
```

## 3. Capture

Open <http://localhost:8000> (admin / the `SPLUNK_PASSWORD` you set), then the
**Frothly BOTS Hunts** app. Capture, at 1280px wide:

- `Frothly intrusion overview` (the KPI board) → `docs/img/overview.png`
- `Azure AD sign-in anomalies` (the choropleth map row) → `docs/img/azure-ad-map.png`
- One scenario dashboard of your choice → `docs/img/scenario.png`

## 4. Embed

Drop the PNGs in `docs/img/` and add a `## Screenshots` section to the top-level
README referencing them. `.png` is already marked binary in `.gitattributes`.
