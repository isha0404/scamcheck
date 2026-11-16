import { useEffect, useRef, useState } from "react";
import { buildSegments } from "./highlight.js";

const MAX_LENGTH = 2000;

const EXAMPLES = [
  {
    label: "Parcel fee",
    text: "Royal Mail: Your parcel could not be delivered due to an unpaid shipping fee of £1.45. Please pay within 12 hours: royalmail-redelivery-uk.com",
  },
  {
    label: "“Hi Mum”",
    text: "Hi Mum, this is my new number, I dropped my phone. Can you send £320 today? It's urgent, I'll pay you back x",
  },
  {
    label: "Genuine delivery",
    text: "Royal Mail: Your parcel from ASOS is due today between 10:15 and 11:15. Track it at royalmail.com/track-your-item",
  },
];

const ICON = { scam: "!", suspicious: "?", no_signs: "✓" };

export default function App() {
  const [message, setMessage] = useState("");
  const [result, setResult] = useState(null);
  const [checkedText, setCheckedText] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const resultRef = useRef(null);

  // When a new result appears, move focus to it so screen-reader and keyboard users land on the answer
  useEffect(() => {
    if (result) resultRef.current?.focus();
  }, [result]);

  async function onCheck(e) {
    e.preventDefault();
    const text = message.trim();
    if (!text) {
      setError("Please paste a message into the box first.");
      return;
    }
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch("/api/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const detail = Array.isArray(data.detail) ? data.detail[0]?.msg : data.detail;
        throw new Error(detail || "Something went wrong. Please try again.");
      }
      setResult(data);
      setCheckedText(text);
    } catch (err) {
      setError(err.message === "Failed to fetch" ? "Couldn't reach ScamCheck. Is the server running?" : err.message);
    } finally {
      setLoading(false);
    }
  }

  function reset() {
    setMessage("");
    setResult(null);
    setError("");
  }

  return (
    <div className="page">
      <header className="top">
        <div className="brand">
          <span className="logo" aria-hidden="true">✓</span> ScamCheck
        </div>
        <p className="privacy">Your message is checked and then forgotten. Nothing is saved.</p>
      </header>

      <main>
        <h1>Is this text message a scam?</h1>
        <p className="lead">Copy the message you received, paste it in the box, and press <b>Check message</b>.</p>

        <form onSubmit={onCheck} noValidate>
          <label htmlFor="message" className="label">The message you received</label>
          <textarea
            id="message"
            value={message}
            onChange={(e) => setMessage(e.target.value.slice(0, MAX_LENGTH))}
            placeholder="Paste the message here…"
            rows={6}
            aria-describedby="count"
          />
          <div className="row">
            <span id="count" className="count">{message.length} / {MAX_LENGTH}</span>
            <span className="examples">
              Try an example:
              {EXAMPLES.map((ex) => (
                <button type="button" key={ex.label} className="chip" onClick={() => { setMessage(ex.text); setResult(null); setError(""); }}>
                  {ex.label}
                </button>
              ))}
            </span>
          </div>
          <div className="actions">
            <button type="submit" className="primary" disabled={loading}>
              {loading ? "Checking…" : "Check message"}
            </button>
            {(message || result) && (
              <button type="button" className="secondary" onClick={reset}>Start again</button>
            )}
          </div>
          {error && <p className="error" role="alert">{error}</p>}
        </form>

        <div aria-live="polite">
          {result && (
            <section className={`result ${result.verdict}`} ref={resultRef} tabIndex={-1} aria-labelledby="verdict">
              <div className="verdict">
                <span className="icon" aria-hidden="true">{ICON[result.verdict]}</span>
                <div>
                  <h2 id="verdict">{result.label}</h2>
                  <p>{result.summary}</p>
                </div>
              </div>
              <Meter risk={result.risk} />

              {result.signals.length > 0 && (
                <>
                  <h3>Warning signs we found</h3>
                  <ul className="signals">
                    {result.signals.map((s, i) => (
                      <li key={i} className={s.severity}>
                        <b>{s.title}</b>
                        <span>{s.detail}</span>
                      </li>
                    ))}
                  </ul>
                </>
              )}

              {result.signals.some((s) => s.spans.length) && (
                <>
                  <h3>Where they are in the message</h3>
                  <blockquote className="message">
                    {buildSegments(checkedText, result.signals).map((seg, i) =>
                      seg.title ? (
                        <mark key={i} className={seg.severity} title={seg.title}>{seg.text}</mark>
                      ) : (
                        <span key={i}>{seg.text}</span>
                      )
                    )}
                  </blockquote>
                </>
              )}

              {result.model_terms.length > 0 && (
                <p className="terms">
                  <b>Words that often appear in scams:</b>{" "}
                  {result.model_terms.map((t) => <span key={t.term} className="term">{t.term}</span>)}
                </p>
              )}

              <h3>What to do</h3>
              <ul className="advice">
                {result.advice.map((a) => <li key={a}>{a}</li>)}
              </ul>
            </section>
          )}
        </div>
      </main>

      <footer>
        ScamCheck gives guidance, not a guarantee. If you're unsure, ask someone you trust, or contact the
        organisation using details you already have.
      </footer>
    </div>
  );
}

function Meter({ risk }) {
  const pct = Math.round(risk * 100);
  return (
    <div className="meter">
      <div className="meter-label"><span>Scam risk</span><b>{pct}%</b></div>
      <div className="meter-track" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} aria-label="Scam risk">
        <div className="meter-fill" style={{ width: `${Math.max(pct, 3)}%` }} />
      </div>
    </div>
  );
}
