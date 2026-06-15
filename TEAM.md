# Vireon — Team Task Split
**Hackathon: Band of Agents | June 12–19, 2026**
**Submission deadline: June 19, 8:30 PM IST**

Architecture is frozen. No new agents. No new modules.
Focus: stabilize → test → polish → demo.

---

## Anubhav (Lead Architect) ~40%

### P0 — Must be done first
- [ ] `cp .env.example .env` — fill in AIML_API_KEY + NVD_API_KEY
- [ ] Create 8 agents at app.band.ai → fill BAND agent IDs in `.env` (10 min)
- [ ] Promo code `BANDHACK26` → activate Band Pro
- [ ] Claim AI/ML API credits at lablab.ai → fill `AIML_API_KEY`

### P1 — Core integration
- [ ] End-to-end smoke test: `python main.py --repo ../SAGE --days 7`
- [ ] Fix any SAGE import errors (sys.path, cfg.set_repo conflicts)
- [ ] Verify challenger_agent + compliance_agent call AI/ML API successfully
- [ ] Verify Band room receives messages from at least 1 agent

### P2 — Polish
- [ ] Write `demo_run.py` — hardcoded mock input for fast demo (no waiting for NVD)
- [ ] Tune confidence fusion weights if numbers look off
- [ ] Final coordinator flow review — make sure the war room story reads cleanly

---

## Harsh (Backend & Platform) ~30%

### Stack
FastAPI + SQLite + Docker

### P0 — FastAPI wrapper around coordinator
```
POST /scan          { repo_path, days }  → { inv_id }
GET  /status/{id}   → { phase, agents_done, agents_running }
GET  /timeline/{id} → [ { timestamp, agent, event, detail, confidence } ]
GET  /summary/{id}  → full investigation summary JSON
GET  /confidence/{id} → [ { agent, confidence } ]  (evolution list)
GET  /graph/{id}    → synapse_graph.json contents
```

### P1 — Session persistence
- SharedState is currently in-memory only — dies if process restarts
- Serialize timeline + results to SQLite after each agent finishes
- `/status` should work even after restart (read from DB)

### P2 — Deployment
- Dockerfile (Python 3.11, install SAGE + Vireon deps)
- docker-compose.yml (vireon + optional postgres upgrade later)
- Deploy to Railway or Render — get a public URL for judges
- Health check endpoint: `GET /health → { status: "ok" }`

### P3 — Reliability
- Wrap coordinator.run() in try/except with error logging to DB
- Retry logic on NVD API rate limits (already in SAGE but confirm it surfaces)
- Request timeout on `/scan` — return inv_id immediately, run async

---

## Vedika (Product & Demo) ~30%

### Stack
React + Tailwind (or plain HTML/CSS if faster) — served from `/ui`

### P0 — War Room Timeline UI
Single page that polls `GET /timeline/{id}` every 2s and renders:
```
[09:00]  🟢 THREAT       started
[09:01]  🟢 THREAT       finished     conf=0.81  12 CVEs, 3 relevant
[09:02]  🟡 STATIC       started
[09:03]  🟡 STATIC       finished     conf=0.74  5 findings
[09:04]  🔵 EXPLOITAB.   started
[09:05]  🔵 EXPLOITAB.   finished     conf=0.89  2 confirmed
[09:06]  🔴 CHALLENGER   started
[09:07]  🔴 CHALLENGER   objection    conf=0.42  1 dismissed
[09:08]  🟣 REMEDIATION  patch gen    conf=0.80
[09:09]  🟠 COMPLIANCE   REJECTED     Authentication check removed
[09:10]  🟣 REMEDIATION  retry #2     conf=0.85
[09:11]  🟠 COMPLIANCE   APPROVED
[09:12]  ✅ VERIFY       PASSED       conf=0.95
[09:13]  ✅ PR           created      #42
```
Color per agent. Live updates as investigation runs.

### P1 — Confidence Evolution Graph
Simple line chart (Chart.js) from `GET /confidence/{id}`:
```
100% ┤                              ● verify
 90% ┤                    ● exploit
 80% ┤       ● threat
 70% ┤  ● static
 60% ┤
 50% ┤                 ● challenger (dip)
     └──────────────────────────────────
       static  threat  exploit  chall  verify
```
This is the visual judges remember.

### P2 — Investigation Summary Page
Reads `GET /summary/{id}` and renders the full card:
- Investigation ID
- Evidence sources with ✓/✗
- Decision log (key decisions only)
- Final outcome: confidence %, patch status, PR link

### P3 — Landing / Trigger Page
Simple form: input repo path + days → `POST /scan` → redirect to War Room UI
This is what you demo live. Judge types a path, hits scan, watches War Room fill up.

### P4 — Demo Recording Assets
- Screen record a full investigation run (use `demo_run.py` for speed)
- Export the War Room timeline as a clean screenshot for slide deck
- README: add architecture diagram + screenshot of War Room UI

---

## Shared / Integration Checkpoints

| Date   | Checkpoint |
|--------|-----------|
| Jun 12 | `.env` filled, Band agents created, end-to-end CLI run works |
| Jun 13 | FastAPI `/scan` + `/timeline` working, Anubhav can test via curl |
| Jun 14 | War Room UI showing live timeline from real scan |
| Jun 15 | Confidence graph live, compliance reject/retry visible in UI |
| Jun 16 | Full demo flow recorded end-to-end |
| Jun 17 | Buffer — bug fixes, polish |
| Jun 18 | README, slides, submission form filled |
| Jun 19 | Submit by 8:30 PM IST |

---

## What NOT to touch
- `agents/` — frozen
- `coordinator/coordinator.py` — frozen (Anubhav only if critical bug)
- `memory/shared_state.py` — frozen
- `sage/` — frozen (SAGE is the engine, Vireon wraps it)

New features go in `ui/`, `api/`, or `scripts/` only.
