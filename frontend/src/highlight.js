// Split a message into plain and highlighted segments using the character
// spans returned by the API. Kept separate from the component so it's easy to test.
//
// React escapes text automatically, so we never insert the message as HTML:
// a scam message containing <script> is shown as harmless text.

export function buildSegments(text, signals) {
  const marks = [];
  for (const s of signals) {
    for (const [start, end] of s.spans) {
      if (start >= 0 && end <= text.length && end > start) {
        marks.push({ start, end, title: s.title, severity: s.severity });
      }
    }
  }
  // Sort, then drop any span that overlaps one already chosen (most severe first).
  const rank = { high: 0, medium: 1, low: 2 };
  marks.sort((a, b) => rank[a.severity] - rank[b.severity] || a.start - b.start);
  const chosen = [];
  for (const m of marks) {
    if (!chosen.some((c) => m.start < c.end && c.start < m.end)) chosen.push(m);
  }
  chosen.sort((a, b) => a.start - b.start);

  const segments = [];
  let pos = 0;
  for (const m of chosen) {
    if (m.start > pos) segments.push({ text: text.slice(pos, m.start) });
    segments.push({ text: text.slice(m.start, m.end), title: m.title, severity: m.severity });
    pos = m.end;
  }
  if (pos < text.length) segments.push({ text: text.slice(pos) });
  return segments;
}
