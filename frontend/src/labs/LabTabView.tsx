import { useEffect, useState } from "react";
import { fetchCatalog, fetchLabStatus, isLive, type LabMeta, type LabStatus } from "./labApi";
import LabConsole from "./LabConsole";
import { toolById } from "../shell/tools";
import { armAndAim } from "../lib/labTabs";

const STATUS_POLL_MS = 4_000;

// Tools that take a single target — offered as "aim here" launchers.
const TARGET_TOOLS: { id: string; label: string }[] = [
  { id: "http_probe", label: "HTTP Probe" },
  { id: "fingerprint", label: "Fingerprint" },
  { id: "tls_audit", label: "TLS" },
  { id: "port_scanner", label: "Port Scan" },
  { id: "nmap", label: "Nmap" },
];

function dotColor(s: LabStatus | undefined): string {
  const st = s?.container.state;
  if (s?.build_status === "error" || st === "exited" || st === "dead") return "var(--danger, #ff5d6c)";
  if (st === "starting" || st === "partial" || s?.build_status === "building") return "var(--amber, #ffc043)";
  if (st === "running") return "var(--accent, #39d98a)";
  return "var(--ink-dim, #586173)";
}

export default function LabTabView({ labId }: { labId: string }) {
  const [lab, setLab] = useState<LabMeta | null | undefined>(undefined);
  const [status, setStatus] = useState<LabStatus | undefined>(undefined);

  useEffect(() => {
    let alive = true;
    fetchCatalog()
      .then((labs) => alive && setLab(labs.find((l) => l.id === labId) ?? null))
      .catch(() => alive && setLab(null));
    return () => {
      alive = false;
    };
  }, [labId]);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const s = await fetchLabStatus(labId);
        if (alive) setStatus(s);
      } catch {
        /* keep last */
      }
    };
    void tick();
    const t = setInterval(tick, STATUS_POLL_MS);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [labId]);

  if (lab === undefined) return <div className="p-4 text-ink-dim">Loading lab…</div>;
  if (lab === null) return <div className="p-4 text-ink-dim">Lab “{labId}” is no longer in the catalog.</div>;

  const address = lab.primary_url.replace(/^https?:\/\//, "") || Object.values(lab.port_map).map((p) => `127.0.0.1:${p}`)[0] || "";
  const live = isLive(status?.container.state);

  function aim(toolId: string) {
    if (!toolById(toolId)) return;
    armAndAim(
      { id: lab!.id, name: lab!.name, primaryUrl: lab!.primary_url, address },
      toolId,
    );
  }

  return (
    <div className="flex h-full flex-col overflow-hidden bg-bg-base">
      {/* Header: name, state, ports, creds. */}
      <div className="shrink-0 border-b border-divider px-5 py-4">
        <div className="flex items-center gap-2.5">
          <span className="h-2.5 w-2.5 rounded-full" style={{ background: dotColor(status) }} />
          <h1 className="text-lg font-bold text-ink-primary">{lab.name}</h1>
          <span className="rounded-full border border-divider px-2 py-0.5 text-[10px] uppercase tracking-wide text-ink-dim">
            {status?.container.state ?? "…"}
          </span>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-x-6 gap-y-1.5 text-[12.5px]">
          {lab.primary_url && (
            <span className="flex items-center gap-2">
              <span className="text-ink-dim">URL</span>
              {live ? (
                <a href={lab.primary_url} target="_blank" rel="noreferrer" className="font-mono text-accent hover:underline">
                  {lab.primary_url}
                </a>
              ) : (
                <span className="font-mono text-ink-muted">{lab.primary_url}</span>
              )}
            </span>
          )}
          {Object.keys(lab.port_map).length > 0 && (
            <span className="flex items-center gap-2">
              <span className="text-ink-dim">Ports</span>
              <span className="font-mono text-ink-muted">
                {Object.entries(lab.port_map).map(([c, h]) => `${h}→${c}`).join(", ")}
              </span>
            </span>
          )}
          {lab.default_creds && (
            <span className="flex items-center gap-2">
              <span className="text-ink-dim">Creds</span>
              <span className="font-mono text-ink-muted">{lab.default_creds}</span>
            </span>
          )}
        </div>

        {/* Aim a tool at this lab. */}
        <div className="mt-3 flex flex-wrap items-center gap-1.5">
          <span className="mr-1 text-[11px] uppercase tracking-wide text-ink-dim">Aim a tool here</span>
          {TARGET_TOOLS.filter((t) => toolById(t.id)).map((t) => (
            <button
              key={t.id}
              onClick={() => aim(t.id)}
              disabled={!live}
              title={live ? `Open ${t.label} targeting this lab` : "Start the lab first"}
              className="rounded-md border border-divider bg-bg-surface px-2.5 py-1 text-[11.5px] text-ink-muted hover:border-accent hover:text-accent disabled:opacity-40"
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Console (sidecar labs only). */}
      <div className="min-h-0 flex-1 p-4">
        {lab.has_sidecar ? (
          <LabConsole lab={lab} />
        ) : (
          <div className="flex h-full items-center justify-center text-center text-[12.5px] text-ink-dim">
            This lab has no scanner sidecar — use the tool launchers above to work against it.
          </div>
        )}
      </div>
    </div>
  );
}
