/**
 * pages/WarRoom.jsx — Live War Room dashboard
 * Owner: Harsh
 *
 * Polls /status and /timeline every 2s while investigation is running.
 * Shows: live timeline, agent status cards, confidence evolution.
 * Redirects to /summary/:inv_id when status === "completed".
 */

import { useEffect, useState } from "react";
import { getStatus, getTimeline } from "../services/api";
import Timeline from "../components/Timeline";
import AgentCard from "../components/AgentCard";
import ConfidenceGraph from "../components/ConfidenceGraph";
import StatusBadge from "../components/StatusBadge";

// Extract inv_id from URL: /war-room/:inv_id
function getInvId() {
  return window.location.pathname.split("/").at(-1);
}

export default function WarRoom() {
  const invId = getInvId();
  const [status, setStatus] = useState(null);
  const [events, setEvents] = useState([]);
  const [lastEventId, setLastEventId] = useState(0);

  useEffect(() => {
    let interval;

    async function poll() {
      try {
        const s = await getStatus(invId);
        setStatus(s);

        const newEvents = await getTimeline(invId, lastEventId);
        if (newEvents.length > 0) {
          setEvents((prev) => [...prev, ...newEvents]);
          setLastEventId(newEvents.at(-1).id);
        }

        if (s.status !== "running") {
          clearInterval(interval);
          if (s.status === "completed") {
            setTimeout(() => {
              window.location.href = `/summary/${invId}`;
            }, 2000);
          }
        }
      } catch (err) {
        console.error("Poll error:", err);
      }
    }

    poll();
    interval = setInterval(poll, 2000);
    return () => clearInterval(interval);
  }, [invId]);

  return (
    <div>
      {/* TODO: Harsh — build the War Room UI here */}
      <h1>War Room — {invId}</h1>
      {status && <StatusBadge status={status.status} />}
      <ConfidenceGraph invId={invId} />
      <Timeline events={events} />
      {/* AgentCard grid — one per agent */}
    </div>
  );
}
