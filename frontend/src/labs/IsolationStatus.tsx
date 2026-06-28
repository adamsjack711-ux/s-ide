import { useEffect, useState } from "react";
import { authFetch } from "../api";

/** Result of the backend egress self-check (`GET /isolation/check`). */
export type IsolationCheck = {
  egress_reachable: boolean;
  checks: { target: string; reachable: boolean }[];
  ok: boolean;
};

/**
 * Status-bar pill that polls the isolation self-check every ~10s.
 *
 * Green "isolated" when egress is blocked (isolation holds, labs may arm);
 * red "EGRESS OPEN" when the host can reach the internet (labs refuse to arm).
 * Exported for the integrator to mount in `StatusBar.tsx`.
 */
export default function IsolationStatus() {
  const [check, setCheck] = useState<IsolationCheck | null>(null);
  const [stale, setStale] = useState(false);

  useEffect(() => {
    let alive = true;
    const poll = async () => {
      try {
        const r = await authFetch("/isolation/check");
        if (!alive) return;
        if (r.ok) {
          setCheck((await r.json()) as IsolationCheck);
          setStale(false);
        } else {
          setStale(true);
        }
      } catch {
        if (alive) setStale(true);
      }
    };
    void poll();
    const t = setInterval(poll, 10_000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  if (!check) {
    return (
      <span className="flex items-center gap-1 rounded px-1.5 text-ink-dim" title="checking isolation…">
        <span>◌</span>
        isolation
      </span>
    );
  }

  const ok = check.ok && !stale;
  const reachable = check.checks.filter((c) => c.reachable).map((c) => c.target);
  const title = ok
    ? "isolation holds — egress blocked; labs may be armed"
    : `egress reachable (${reachable.join(", ") || "?"}) — labs refuse to arm (fail closed)`;

  return (
    <span
      title={title}
      className={`flex items-center gap-1 rounded px-1.5 ${ok ? "text-success" : "text-danger"}`}
    >
      <span>{ok ? "●" : "▲"}</span>
      {ok ? "isolated" : "EGRESS OPEN"}
    </span>
  );
}
