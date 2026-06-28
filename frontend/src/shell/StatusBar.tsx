import { useEffect, useState } from "react";
import { StatusDot } from "performative-ui";
import { BACKEND_URL } from "../api";
import { setMode, useMode } from "../lib/mode";
import { listEngagements, useActiveEngagementId, type Engagement } from "../lib/engagement";
import IsolationStatus from "../labs/IsolationStatus";
import { listAttestations } from "../lib/safety";
import { emit, useBus } from "./bus";

type Conn = "connecting" | "online" | "offline";

/**
 * Bottom status bar: active engagement · scope-mode security gate · backend
 * health. The mode toggle is the deliberate "scoped vs. scratch" gate; it is
 * window-level state (Phase 5 makes it truly per-window).
 */
export default function StatusBar() {
  const activeId = useActiveEngagementId();
  const mode = useMode();
  const [conn, setConn] = useState<Conn>("connecting");
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [attested, setAttested] = useState(0);

  const refreshAttestations = () => {
    listAttestations(activeId).then((a) => setAttested(a.length)).catch(() => setAttested(0));
  };
  useEffect(refreshAttestations, [activeId]);
  useBus("attestationsChanged", refreshAttestations);

  useEffect(() => {
    let alive = true;
    const ping = async () => {
      try {
        const r = await fetch(`${BACKEND_URL}/health`);
        if (alive) setConn(r.ok ? "online" : "offline");
      } catch {
        if (alive) setConn("offline");
      }
    };
    void ping();
    const t = setInterval(ping, 5_000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  useEffect(() => {
    listEngagements().then(setEngagements).catch(() => {});
  }, [activeId]);

  const active = engagements.find((e) => e.id === activeId);
  const scoped = mode === "engagement";

  return (
    <div className="flex h-6 items-center gap-4 border-t border-divider bg-bg-sidebar px-3 text-[11px] text-ink-muted">
      <span className="flex items-center gap-1">
        <span className="text-accent">⛬</span>
        {active ? active.name : "no engagement"}
      </span>

      <button
        onClick={() => setMode(scoped ? "lab" : "engagement")}
        title="Toggle scope enforcement (scoped engagement ↔ unscoped scratch)"
        className={`rounded px-1.5 ${scoped ? "text-success" : "text-amber"}`}
      >
        {scoped ? "scope ✓ engagement" : "scratch ⚠ unscoped"}
      </button>

      <button
        onClick={() => emit("openAttestation", {})}
        title="Authorization attestation — required for active tools against external targets"
        className={`rounded px-1.5 ${attested > 0 ? "text-success" : "text-amber"}`}
      >
        {attested > 0 ? `attested ✓ ${attested}` : "no attestation"}
      </button>

      <span className="ml-auto flex items-center gap-3">
        <IsolationStatus />
        <span className="flex items-center gap-1.5">
          <StatusDot color={conn === "online" ? "#3fb950" : conn === "offline" ? "#f85149" : "#d29922"} />
          backend {conn === "online" ? "8765" : conn}
        </span>
      </span>
    </div>
  );
}
