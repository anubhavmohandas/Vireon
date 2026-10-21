# Vireon Frontend

React + Vite UI for the Vireon autonomous security investigation platform.

## Run

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
```

The dev server proxies `/api` and `/health` to the FastAPI backend on
`http://localhost:8000` (see `vite.config.js`), so run `uvicorn api.main:app
--port 8000` alongside it.

## Demo mode (no backend needed)

The API routes in `api/routes/*.py` currently return 501. Until they're
implemented, the UI runs on built-in mock data that simulates a full live
investigation (timeline events stream in over ~22s, confidence rises then dips
at the Challenger, Compliance rejects once and retries, then Verification
passes). This is on by default.

- `VITE_USE_MOCK=0` — turn mock off, use only the real backend.
- `VITE_API_URL=https://your-api` — point at a deployed backend.

The mock also kicks in automatically if a live call returns 501/404 or the
server is unreachable, so the demo never dead-ends mid-presentation.

## Routes

| Route | Page | Purpose |
|-------|------|---------|
| `/` | `pages/Landing.jsx` | Hero, pipeline overview, start scan |
| `/war-room/:invId` | `pages/WarRoom.jsx` | Live dashboard — polls status + timeline |
| `/summary/:invId` | `pages/Summary.jsx` | Final report — agent results, decisions, graph |

## Structure

- `src/agents.js` — single source of truth for agent colors, icons, labels
- `src/services/api.js` — API client (matches `api/models.py` shapes exactly)
- `src/services/mock.js` — demo data with the same shapes
- `src/components/` — Timeline, ConfidenceGraph, GraphViewer, AgentCard, StatusBadge
- `src/index.css` — design tokens (light off-white base, violet command accent, per-agent colors)

## Libraries

- `react-router-dom` — routing
- `recharts` — confidence evolution chart
- `react-force-graph-2d` — knowledge graph
