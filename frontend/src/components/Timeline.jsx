/**
 * components/Timeline.jsx — Live event timeline
 * Owner: Harsh
 *
 * Props:
 *   events: Array<{ id, agent, event_type, detail, timestamp }>
 *
 * Renders a scrollable feed of timeline events with agent label + timestamp.
 */

export default function Timeline({ events = [] }) {
  if (events.length === 0) return <p>No events yet…</p>;

  return (
    <ul>
      {/* TODO: Harsh — replace with styled timeline */}
      {events.map((e) => (
        <li key={e.id}>
          <strong>{e.agent}</strong> [{e.event_type}] — {e.detail}
          <em> {new Date(e.timestamp).toLocaleTimeString()}</em>
        </li>
      ))}
    </ul>
  );
}
