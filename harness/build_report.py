"""Render the scenarios into a single self-contained static HTML report.

Output lands at docs/index.html so it can be served as-is or published with
GitHub Pages (Settings -> Pages -> main / docs). No external assets, no JS
framework: one file, inline CSS, a few lines of vanilla JS for the hunt toggles.
"""
from __future__ import annotations

import html
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "scenarios"
OUTPUT = ROOT / "docs" / "index.html"


@dataclass
class Hunt:
    file: str
    question: str
    expected: str
    field: str | None
    spl: str


@dataclass
class Scenario:
    slug: str
    number: str
    title: str
    summary: str
    hunts: list[Hunt]
    techniques: list[tuple[str, str]]
    detections: list[str]


def parse_title(readme: str) -> str:
    """First markdown H1, with the leading 'NN — ' prefix stripped."""
    for line in readme.splitlines():
        if line.startswith("# "):
            text = line[2:].strip()
            return re.sub(r"^\d+\s*[—-]\s*", "", text)
    return ""


def parse_summary(readme: str) -> str:
    """First non-empty paragraph of the body of the first '## ' section."""
    lines = readme.splitlines()
    in_section = False
    para: list[str] = []
    for line in lines:
        if line.startswith("## "):
            if in_section and para:
                break
            in_section = True
            continue
        if not in_section:
            continue
        if line.strip():
            para.append(line.strip())
        elif para:
            break
    return _strip_md(" ".join(para))


def _strip_md(text: str) -> str:
    """Drop the inline markdown the report has no renderer for (links, code, emphasis)."""
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = text.replace("`", "")
    return re.sub(r"\*\*?", "", text)


def build_matrix(scenarios: list[Scenario]) -> tuple[list[tuple[str, str]], dict[str, set[str]]]:
    """Return (sorted unique techniques, technique-id -> set of scenario numbers)."""
    names: dict[str, str] = {}
    coverage: dict[str, set[str]] = {}
    for scenario in scenarios:
        for tid, name in scenario.techniques:
            names[tid] = name
            coverage.setdefault(tid, set()).add(scenario.number)
    ordered = [(tid, names[tid]) for tid in sorted(names)]
    return ordered, coverage


def load_scenarios() -> list[Scenario]:  # pragma: no cover
    scenarios: list[Scenario] = []
    if not SCENARIOS.exists():
        return scenarios
    for path in sorted(SCENARIOS.iterdir()):
        if not path.is_dir() or not re.match(r"\d+-", path.name):
            continue
        readme_file = path / "README.md"
        answers_file = path / "answers.yaml"
        if not readme_file.exists() or not answers_file.exists():
            continue
        readme = readme_file.read_text(encoding="utf-8")
        answers = yaml.safe_load(answers_file.read_text()) or {}
        attack_file = path / "attack.yaml"
        attack = yaml.safe_load(attack_file.read_text()) if attack_file.exists() else {}
        hunts: list[Hunt] = []
        for entry in (answers or {}).get("hunts", []):
            name = entry.get("file")
            if not name:
                continue
            spl_path = path / "hunts" / name
            spl = spl_path.read_text(encoding="utf-8").strip() if spl_path.exists() else ""
            hunts.append(
                Hunt(
                    file=name,
                    question=entry.get("question", ""),
                    expected=str(entry.get("expected", "")),
                    field=entry.get("field"),
                    spl=spl,
                )
            )
        techniques = [
            (t["id"], t.get("name", ""))
            for t in (attack or {}).get("techniques", [])
            if t.get("id")
        ]
        det_file = path / "detections.yaml"
        det_data = yaml.safe_load(det_file.read_text()) if det_file.exists() else {}
        detections = [d["name"] for d in (det_data or {}).get("detections", []) if d.get("name")]
        scenarios.append(
            Scenario(
                slug=path.name,
                number=path.name.split("-", 1)[0],
                title=parse_title(readme),
                summary=parse_summary(readme),
                hunts=hunts,
                techniques=techniques,
                detections=detections,
            )
        )
    return scenarios


def _esc(text: str) -> str:
    return html.escape(text)


def render(scenarios: list[Scenario]) -> str:
    techniques, coverage = build_matrix(scenarios)
    numbers = [s.number for s in scenarios]

    matrix_head = "".join(f'<th scope="col">{_esc(n)}</th>' for n in numbers)
    matrix_rows = []
    hit_cell = (
        '<td class="hit"><span aria-hidden="true">●</span>'
        '<span class="sr">covered</span></td>'
    )
    miss_cell = '<td class="miss"><span class="sr">not covered</span></td>'
    for tid, name in techniques:
        cells = "".join(hit_cell if n in coverage[tid] else miss_cell for n in numbers)
        matrix_rows.append(
            f'<tr><th class="tech" scope="row"><code>{_esc(tid)}</code> '
            f"{_esc(name)}</th>{cells}</tr>"
        )

    cards = []
    for s in scenarios:
        chips = "".join(f'<span class="chip">{_esc(tid)}</span>' for tid, _ in s.techniques)
        hunt_blocks = []
        for i, h in enumerate(s.hunts, 1):
            field = f' <span class="field">→ {_esc(h.field)}</span>' if h.field else ""
            toggle = (
                "const h=this.parentNode;h.classList.toggle('open');"
                "this.setAttribute('aria-expanded',h.classList.contains('open'))"
            )
            hunt_blocks.append(
                f'<div class="hunt">'
                f'<button class="hq" aria-expanded="false" onclick="{toggle}">'
                f'<span class="num">{i}</span>{_esc(h.question)}'
                f'<span class="ans">{_esc(h.expected)}</span></button>'
                f'<div class="spl"><pre>{_esc(h.spl)}</pre>'
                f'<div class="meta">{_esc(h.file)}{field}</div></div>'
                f"</div>"
            )
        det_html = ""
        if s.detections:
            items = "".join(f"<li>{_esc(d)}</li>" for d in s.detections)
            det_html = f'<div class="dets"><span>Detections</span><ul>{items}</ul></div>'
        cards.append(
            f'<section class="card" id="{_esc(s.slug)}">'
            f'<h3><span class="badge">{_esc(s.number)}</span>{_esc(s.title)}</h3>'
            f'<p class="summary">{_esc(s.summary)}</p>'
            f'<div class="chips">{chips}</div>'
            f'<div class="hunts">{"".join(hunt_blocks)}</div>'
            f"{det_html}"
            f"</section>"
        )

    total_hunts = sum(len(s.hunts) for s in scenarios)
    total_detections = sum(len(s.detections) for s in scenarios)
    return _PAGE.format(
        scenario_count=len(scenarios),
        hunt_count=total_hunts,
        detection_count=total_detections,
        technique_count=len(techniques),
        matrix_head=matrix_head,
        matrix_rows="".join(matrix_rows),
        cards="".join(cards) or '<p class="summary">No scenarios yet.</p>',
    )


def main() -> int:  # pragma: no cover
    scenarios = load_scenarios()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(render(scenarios), encoding="utf-8")
    print(f"Wrote {OUTPUT} ({len(scenarios)} scenarios)")
    return 0


_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Documented Splunk hunts over the Boss of the SOC v3 dataset.">
<title>Splunk BOTS v3 threat hunts</title>
<style>
:root {{ --bg:#0d1117; --panel:#161b22; --line:#30363d; --text:#c9d1d9;
  --muted:#8b949e; --accent:#58a6ff; --hit:#3fb950; --ans:#d29922; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text);
  font:15px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }}
.wrap {{ max-width:980px; margin:0 auto; padding:32px 20px 80px; }}
header h1 {{ margin:0 0 4px; font-size:28px; }}
header p {{ margin:0; color:var(--muted); }}
.stats {{ display:flex; flex-wrap:wrap; gap:24px; margin:24px 0 8px; }}
.stat {{ background:var(--panel); border:1px solid var(--line); border-radius:8px;
  padding:12px 18px; }}
.stat b {{ display:block; font-size:24px; color:var(--accent); }}
.stat span {{ color:var(--muted); font-size:13px; }}
.sr {{ position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden;
  clip:rect(0,0,0,0); white-space:nowrap; border:0; }}
h2 {{ margin:40px 0 12px; font-size:18px; border-bottom:1px solid var(--line);
  padding-bottom:6px; }}
.matrix-wrap {{ overflow-x:auto; }}
table.matrix {{ border-collapse:collapse; width:100%; font-size:13px; }}
table.matrix th, table.matrix td {{ border:1px solid var(--line); padding:6px 8px;
  text-align:center; }}
table.matrix th.tech {{ text-align:left; white-space:nowrap; font-weight:400; }}
table.matrix td.hit {{ color:var(--hit); font-size:16px; }}
table.matrix code {{ color:var(--accent); }}
.card {{ background:var(--panel); border:1px solid var(--line); border-radius:10px;
  padding:18px 20px; margin:16px 0; }}
.card h3 {{ margin:0 0 8px; font-size:18px; display:flex; align-items:center; gap:10px; }}
.badge {{ background:var(--accent); color:#0d1117; border-radius:6px; padding:1px 9px;
  font-size:14px; font-weight:700; }}
.summary {{ color:var(--muted); margin:0 0 12px; }}
.chips {{ margin-bottom:12px; }}
.chip {{ display:inline-block; background:#1f6feb22; color:var(--accent);
  border:1px solid #1f6feb55; border-radius:20px; padding:1px 10px; font-size:12px;
  margin:0 6px 6px 0; }}
.hunt {{ border-top:1px solid var(--line); }}
.hq {{ width:100%; text-align:left; background:none; border:0; color:var(--text);
  padding:10px 0; cursor:pointer; font-size:14px; display:flex; align-items:center;
  gap:10px; }}
.hq:focus-visible {{ outline:2px solid var(--accent); outline-offset:2px; }}
.hq .num {{ color:var(--muted); }}
.hq .ans {{ margin-left:auto; color:var(--ans); font-family:ui-monospace,monospace;
  font-size:13px; }}
.spl {{ max-height:0; overflow:hidden; transition:max-height .25s ease; }}
.hunt.open .spl {{ max-height:1200px; }}
.spl pre {{ background:#0d1117; border:1px solid var(--line); border-radius:6px;
  padding:12px; overflow:auto; font-size:13px; color:#e6edf3;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
.meta {{ color:var(--muted); font-size:12px; margin:0 0 12px; }}
.field {{ color:var(--accent); }}
.dets {{ border-top:1px solid var(--line); padding-top:10px; }}
.dets span {{ color:var(--muted); font-size:12px; text-transform:uppercase;
  letter-spacing:.04em; }}
.dets ul {{ margin:6px 0 0; padding-left:18px; }}
.dets li {{ font-size:13px; margin:2px 0; }}
.links {{ margin:12px 0 0; color:var(--muted); font-size:13px; }}
footer {{ margin-top:48px; color:var(--muted); font-size:13px;
  border-top:1px solid var(--line); padding-top:16px; }}
a {{ color:var(--accent); }}
</style>
</head>
<body>
<main class="wrap">
<header>
<h1>Splunk BOTS v3 threat hunts</h1>
<p>Threat hunting walkthroughs for Splunk's Boss of the SOC v3 dataset.</p>
</header>
<div class="stats">
<div class="stat"><b>{scenario_count}</b><span>scenarios</span></div>
<div class="stat"><b>{hunt_count}</b><span>hunts</span></div>
<div class="stat"><b>{detection_count}</b><span>detections</span></div>
<div class="stat"><b>{technique_count}</b><span>ATT&amp;CK techniques</span></div>
</div>
<p class="links">Deployable detections ship as a Splunk app
(<code>splunk_app/froth_bots_hunts</code>). ATT&amp;CK coverage is also exported as a
<a href="attack-navigator-layer.json">Navigator layer</a>.</p>
<h2>ATT&amp;CK coverage</h2>
<div class="matrix-wrap">
<table class="matrix">
<thead><tr><th class="tech" scope="col">Technique</th>{matrix_head}</tr></thead>
<tbody>{matrix_rows}</tbody>
</table>
</div>
<h2>Scenarios</h2>
{cards}
<footer>Generated from the scenario sources by
<code>harness/build_report.py</code>. Click a hunt to see its SPL.</footer>
</main>
</body>
</html>
"""


if __name__ == "__main__":
    sys.exit(main())
