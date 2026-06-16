# Vireon Frontend
Owner: Harsh

## Stack
React + Vite (recommended) or plain HTML/JS — your call.

## Dev setup (React/Vite)
```bash
cd frontend
npm create vite@latest . -- --template react
npm install
npm run dev        # runs on http://localhost:5173
```

## API base URL
All API calls go to `http://localhost:8000` (Vedika's FastAPI server).
Set in `src/services/api.js`.

## Pages
| Route | File | Purpose |
|-------|------|---------|
| `/` | `pages/Landing.jsx` | Landing / start scan |
| `/war-room/:inv_id` | `pages/WarRoom.jsx` | Live War Room dashboard |
| `/summary/:inv_id` | `pages/Summary.jsx` | Final investigation report |

## Components
| File | Purpose |
|------|---------|
| `components/Timeline.jsx` | Rich event timeline |
| `components/ConfidenceGraph.jsx` | Confidence evolution chart |
| `components/GraphViewer.jsx` | Dependency/CVE knowledge graph |
| `components/AgentCard.jsx` | Individual agent result card |
| `components/StatusBadge.jsx` | running / completed / aborted badge |

## API calls
All in `src/services/api.js` — import from there, don't call fetch directly in components.
