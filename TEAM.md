# Vireon — Team Task Split
**Hackathon: Band of Agents | June 12–19, 2026**
**Submission deadline: June 19, 8:30 PM IST**

Architecture is frozen. No new agents. No new modules.
Focus: stabilize → test → polish → demo.

---

## Anubhav — Architecture Lead ~40%

> Own the brain. Everything that makes agents think correctly.

- Coordinator logic + orchestration flow
- SharedState + confidence fusion
- Prompt engineering (challenger + compliance system prompts)
- Final integration (wire Vedika's API + Harsh's UI together)
- Bug fixes on coordinator/agent logic
- Demo flow script (`demo_run.py`)
- Band room setup (done)
- Code reviews for both teammates

### P0 this week
- [ ] Claim AI/ML API credits → fill `AIML_API_KEY` in `.env`
- [ ] Smoke test: `python main.py --repo ../SAGE --days 7`
- [ ] Fix any SAGE import path issues
- [ ] Write `demo_run.py` — mock input for fast demo (no waiting on NVD)

---

## Vedika — Backend & Integration Lead ~30%

> Own backend reliability. If it breaks, you fix it.

### 1. Agent improvements
- `challenger_agent.py` — improve JSON parsing robustness, add fallback if LLM returns malformed output
- `compliance_agent.py` — same, plus tune the rejection criteria prompt
- `verification_agent.py` — handle edge case where no tests exist in scanned repo

### 2. FastAPI backend
```
POST /scan          { repo_path, days }  →  { inv_id }
GET  /status/{id}   →  { phase, agents_done }
GET  /timeline/{id} →  [ timeline events ]
GET  /summary/{id}  →  full investigation summary
GET  /confidence/{id} →  [ confidence evolution ]
GET  /graph/{id}    →  synapse_graph.json contents
GET  /health        →  { status: "ok" }
```
- Run coordinator in background task (return `inv_id` immediately)
- Store timeline + results in SQLite so `/timeline` works even mid-run

### 3. AI/ML API testing
- Verify challenger + compliance agents hit AI/ML API correctly
- Test with a real repo (use SAGE itself as the scan target)
- Document token usage per run (stay within $10 budget)

### 4. End-to-end integration test
Verify full flow completes without crash:
```
Threat → Static → Exploitability → Challenger
→ Remediation → Compliance → Verification → PR
```

### 5. Error handling + retries
- NVD rate limit handling (already in SAGE — verify it surfaces cleanly)
- Graceful degradation if an agent fails (log + continue, don't crash coordinator)
- Retry on Band connection failure

---

## Harsh — Frontend & Demo Lead ~30%

> Own the judge experience. What they see = what they remember.

### 1. War Room Dashboard (main page)
Live-updating feed of agent activity. Polls `GET /timeline/{id}` every 2s.
```
[09:00]  🟢 THREAT        started
[09:01]  🟢 THREAT        finished    conf=0.81   12 CVEs, 3 relevant
[09:02]  🟡 STATIC        finished    conf=0.74   5 findings
[09:03]  🔵 EXPLOITAB.    finished    conf=0.89   2 confirmed
[09:04]  🔴 CHALLENGER    objection   conf=0.42   1 dismissed
[09:05]  🟣 REMEDIATION   patch gen
[09:06]  🟠 COMPLIANCE    REJECTED    Auth check removed
[09:07]  🟣 REMEDIATION   retry #2
[09:08]  🟠 COMPLIANCE    APPROVED
[09:09]  ✅ VERIFY        PASSED      conf=0.95
[09:10]  ✅ PR            created     #42
```

### 2. Confidence Evolution Graph
Line chart from `GET /confidence/{id}`. Show confidence rising/falling as agents finish.
```
100% ┤                              ● verify
 90% ┤                    ● exploit
 80% ┤       ● threat
 70% ┤  ● static
 60% ┤
 50% ┤                 ● challenger (dip)
     └─────────────────────────────────
```

### 3. Investigation Summary Page
Reads `GET /summary/{id}`. Renders the final card:
- INV-XXXXX header
- Evidence sources with ✓/✗
- Decision log (key decisions)
- Fused confidence %, patch status, PR link

### 4. Synapse Graph Viewer
Reads `GET /graph/{id}`. Renders `synapse_graph.json` as interactive node graph.
Use D3.js or vis.js — nodes = functions/CVEs, edges = call relationships.

### 5. Landing / Trigger Page
Simple form: repo path + days → `POST /scan` → redirect to War Room.
This is the live demo entry point. Keep it clean.

### 6. Landing page sections
- Hero: "Autonomous Security Investigation Platform"
- Architecture diagram (the agent flow)
- Features: War Room, Confidence Tracking, Challenger Debate, Self-verifying patches
- Screenshots of the UI

### 7. Polish
- Loading states between phases
- Color per agent (consistent across timeline + graph)
- Mobile-responsive (judges may view on phone)

---

## Integration Checkpoints

| Date   | Checkpoint |
|--------|-----------|
| Jun 12 | `.env` filled, smoke test passes, kickoff stream watched |
| Jun 13 | FastAPI `/scan` + `/timeline` working, Anubhav tests via curl |
| Jun 14 | War Room UI showing live timeline from real scan |
| Jun 15 | Confidence graph live, compliance reject/retry visible in UI |
| Jun 16 | Full demo recorded end-to-end |
| Jun 17 | Buffer — bug fixes, polish |
| Jun 18 | README, slides, submission form filled |
| Jun 19 | Submit by 8:30 PM IST |

---

## What NOT to touch
- `agents/` — frozen (Vedika fixes robustness only, no new logic)
- `coordinator/coordinator.py` — Anubhav only
- `memory/shared_state.py` — frozen
- `sage/` — frozen

New features go in `api/`, `ui/`, or `scripts/` only.
