/**
 * Labs — vulnerable apps you can spin up locally and aim the IDE's tools at.
 *
 * Rebuilt to match HackingPal's proven flow (the rail version "wasn't spinning
 * up" because failed builds/starts did nothing visible). This version:
 *
 *   • Renders FULL-WIDTH as a main view (default export, no props).
 *   • A runtime banner at top — polls /labs/runtime/status; "Docker is not
 *     running" + start guidance when down, green "Docker ready" when up.
 *   • A grid of lab cards from /labs/catalog, each polling /labs/{id}/status
 *     for a live container-state dot.
 *   • Build / Start / Stop / Open / Attach-to-engagement actions, with state-
 *     aware labels AND surfaced error text — the actual "aren't spinning up"
 *     fix is showing why a build/start failed instead of silently no-op'ing.
 *   • Per-lab suggested-steps rendered as chips that emit("openTool") into the
 *     shell bus, mapping HackingPal route names → s-ide tool ids.
 *
 * Everything degrades gracefully: fetch errors render inline, never crash.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Button, EyebrowPill, GlassCard, StatusDot } from "performative-ui";
import { authFetch } from "../api";
import { emit } from "../shell/bus";
import ViewModeToggle from "../shell/ViewModeToggle";
import { useViewMode } from "../lib/viewMode";
import {
  createEngagement,
  getActiveEngagementId,
  setActiveEngagementId,
  useActiveEngagementId,
} from "../lib/engagement";

// ── Backend contract types ───────────────────────────────────────────────────

type SuggestedStep = {
  label: string;
  route: string;
  query: Record<string, string>;
  description: string;
};

type Lab = {
  id: string;
  name: string;
  summary: string;
  kind: string;
  category: string;
  image_tag: string;
  container_name: string;
  port_map: Record<string, number>;
  primary_url: string;
  default_creds: string | null;
  has_sidecar: boolean;
  suggested_steps: SuggestedStep[];
};

type CatalogResponse = { labs: Lab[] };

type RuntimeStatus = {
  state: string; // "ok" | "binary_missing" | "daemon_stopped" | ...
  needs_install?: boolean;
  needs_start?: boolean;
  colima_path?: string | null;
  docker_path?: string | null;
  hint?: string;
  command?: string | null;
};

type ContainerState =
  | "running"
  | "exited"
  | "missing"
  | "created"
  | "paused"
  | "dead"
  | "partial"
  | "starting"
  | "unknown";

type LabStatus = {
  container: { state: ContainerState; status?: string };
  build_status?: "idle" | "building" | "built" | "error";
  build_error?: string | null;
};

type ApiError = { error?: string; code?: string; detail?: string };

// ── Route → tool-id map ──────────────────────────────────────────────────────
// HackingPal's suggested_steps carry HackingPal route names. Map them onto the
// s-ide tool registry ids (src/shell/tools/*). Unknown routes are dropped so a
// chip never points at a tool that doesn't exist. `labs` is a sidecar route
// with no tool surface here — intentionally omitted.
const ROUTE_TO_TOOL: Record<string, string> = {
  fingerprint: "fingerprint",
  http: "http_probe",
  nmap: "nmap",
  ports: "port_scanner",
  sqli: "sqli",
  xss: "xss",
  cmdi: "cmdi",
  lfi: "lfi",
  jwt: "jwt",
  smb: "smb_enum",
  // dirb / hash / audit / labs → no s-ide tool; chips for these are skipped.
};

const RUNTIME_POLL_MS = 8_000;
const STATUS_POLL_MS = 4_000;

// ── Helpers ──────────────────────────────────────────────────────────────────

async function readError(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as ApiError;
    return body.error || body.detail || body.code || `HTTP ${res.status}`;
  } catch {
    return `HTTP ${res.status}`;
  }
}

function errString(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function isLive(state: ContainerState | undefined): boolean {
  return state === "running" || state === "partial" || state === "starting";
}

function dotColor(status: LabStatus | undefined): string {
  const state = status?.container.state;
  if (status?.build_status === "error") return "var(--danger, #ff5d6c)";
  if (status?.build_status === "building" || state === "starting")
    return "var(--amber, #ffc043)";
  if (state === "running") return "var(--accent, #39d98a)";
  if (state === "partial") return "var(--amber, #ffc043)";
  if (state === "exited" || state === "dead") return "var(--danger, #ff5d6c)";
  return "var(--ink-dim, #586173)";
}

function stateLabel(status: LabStatus | undefined): string {
  if (status?.build_status === "error") return "BUILD ERROR";
  if (status?.build_status === "building") return "BUILDING";
  const state = status?.container.state;
  switch (state) {
    case "running":
      return "RUNNING";
    case "partial":
      return "PARTIAL";
    case "starting":
      return "STARTING";
    case "exited":
      return "STOPPED";
    case "dead":
      return "DEAD";
    case "missing":
    case undefined:
      return "NOT STARTED";
    default:
      return state.toUpperCase();
  }
}

function categoryClasses(cat: string): string {
  switch (cat) {
    case "Web":
      return "border-accent/40 text-accent bg-accent/10";
    case "API":
      return "border-phos/40 text-phos bg-phos/10";
    case "CVE":
      return "border-danger/40 text-danger bg-danger/10";
    case "Network":
      return "border-amber/40 text-amber bg-amber/10";
    default:
      return "border-divider text-ink-muted bg-bg-card";
  }
}

// ── Root view ────────────────────────────────────────────────────────────────

export default function LabsView() {
  const [labs, setLabs] = useState<Lab[]>([]);
  const [runtime, setRuntime] = useState<RuntimeStatus | null>(null);
  const [statuses, setStatuses] = useState<Record<string, LabStatus>>({});
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [labsMode] = useViewMode("labs");

  const activeEngagementId = useActiveEngagementId();

  // ── Catalog (once) ─────────────────────────────────────────────────────────
  const loadCatalog = useCallback(async () => {
    try {
      const res = await authFetch("/labs/catalog");
      if (!res.ok) {
        setCatalogError(await readError(res));
        return;
      }
      const data = (await res.json()) as CatalogResponse;
      setLabs(data.labs ?? []);
      setCatalogError(null);
    } catch (e) {
      setCatalogError(errString(e));
    }
  }, []);

  useEffect(() => {
    void loadCatalog();
  }, [loadCatalog]);

  // ── Runtime status poll ────────────────────────────────────────────────────
  const loadRuntime = useCallback(async () => {
    try {
      const res = await authFetch("/labs/runtime/status");
      if (res.ok) setRuntime((await res.json()) as RuntimeStatus);
    } catch {
      /* leave previous state; banner will keep showing last known */
    }
  }, []);

  useEffect(() => {
    void loadRuntime();
    const t = setInterval(loadRuntime, RUNTIME_POLL_MS);
    return () => clearInterval(t);
  }, [loadRuntime]);

  // ── Per-lab status poll ────────────────────────────────────────────────────
  const refreshStatus = useCallback(async (labId: string) => {
    try {
      const res = await authFetch(`/labs/${labId}/status`);
      if (!res.ok) return;
      const s = (await res.json()) as LabStatus;
      setStatuses((prev) => ({ ...prev, [labId]: s }));
    } catch {
      /* swallow poll errors — next tick retries */
    }
  }, []);

  useEffect(() => {
    if (labs.length === 0) return;
    const tick = () => {
      for (const lab of labs) void refreshStatus(lab.id);
    };
    tick();
    const t = setInterval(tick, STATUS_POLL_MS);
    return () => clearInterval(t);
  }, [labs, refreshStatus]);

  const runtimeOk = runtime?.state === "ok";

  return (
    <div className="flex h-full flex-col overflow-auto bg-bg-base">
      <header className="border-b border-divider px-6 pt-5 pb-4">
        <EyebrowPill>Training</EyebrowPill>
        <h1 className="mt-2 text-lg font-bold tracking-wide text-ink-primary">Labs</h1>
        <div className="mt-4">
          <RuntimeBanner runtime={runtime} onRecheck={loadRuntime} />
        </div>
      </header>

      <div className="flex-1 px-6 py-5">
        {catalogError && (
          <InlineError
            message={`Couldn't load the lab catalog — ${catalogError}`}
            onRetry={loadCatalog}
          />
        )}

        {!catalogError && labs.length === 0 && (
          <div className="text-sm text-ink-dim">Loading labs…</div>
        )}

        {labs.length > 0 && (
          <div className="mb-3 flex items-center justify-end">
            <ViewModeToggle storageKey="labs" />
          </div>
        )}
        <div
          className={
            labsMode === "list"
              ? "grid grid-cols-1 gap-2.5"
              : "grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3"
          }
        >
          {labs.map((lab) => (
            <LabCard
              key={lab.id}
              lab={lab}
              status={statuses[lab.id]}
              runtimeOk={runtimeOk}
              activeEngagementId={activeEngagementId}
              onRefresh={() => refreshStatus(lab.id)}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Runtime banner ───────────────────────────────────────────────────────────

function RuntimeBanner({
  runtime,
  onRecheck,
}: {
  runtime: RuntimeStatus | null;
  onRecheck: () => void;
}) {
  if (runtime?.state === "ok") {
    return (
      <div className="flex items-center gap-2.5 rounded border border-accent/40 bg-accent/10 px-3 py-2 text-[12px]">
        <StatusDot color="var(--accent, #39d98a)" />
        <span className="font-semibold text-accent">Docker ready</span>
      </div>
    );
  }

  // Down / unknown. Surface the backend's hint + start command if present.
  const headline =
    runtime?.needs_install || runtime?.state === "binary_missing"
      ? "No container runtime installed"
      : "Docker is not running";
  const hint =
    runtime?.hint ??
    "Labs can't build or start until the container runtime is up.";
  const command =
    runtime?.command ?? (runtime?.state ? "colima start" : null);

  return (
    <div className="rounded border border-amber/40 bg-amber/10 px-3 py-2.5 text-[12px]">
      <div className="flex items-center gap-2.5">
        <StatusDot color="var(--amber, #ffc043)" static={false} />
        <span className="font-semibold text-amber">{headline}</span>
        <div className="flex-1" />
        <Button variant="ghost" size="sm" onClick={onRecheck}>
          Re-check
        </Button>
      </div>
      <p className="mt-1.5 pl-[18px] text-ink-muted">{hint}</p>
      {command && (
        <div className="mt-2 pl-[18px]">
          <div className="mb-1 text-[10px] uppercase tracking-widest text-ink-dim">
            Run this in a terminal
          </div>
          <pre className="select-all overflow-auto rounded border border-divider bg-bg-base px-3 py-2 font-mono text-[12px] text-ink-primary">
            {command}
          </pre>
        </div>
      )}
    </div>
  );
}

// ── Lab card ─────────────────────────────────────────────────────────────────

function LabCard({
  lab,
  status,
  runtimeOk,
  activeEngagementId,
  onRefresh,
}: {
  lab: Lab;
  status: LabStatus | undefined;
  runtimeOk: boolean;
  activeEngagementId: string | null;
  onRefresh: () => void;
}) {
  const [pending, setPending] = useState<"build" | "start" | "stop" | "attach" | null>(
    null,
  );
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const noticeTimer = useRef<number | null>(null);
  useEffect(
    () => () => {
      if (noticeTimer.current != null) window.clearTimeout(noticeTimer.current);
    },
    [],
  );

  const flash = useCallback((msg: string) => {
    setNotice(msg);
    if (noticeTimer.current != null) window.clearTimeout(noticeTimer.current);
    noticeTimer.current = window.setTimeout(() => setNotice(null), 6_000);
  }, []);

  const building = status?.build_status === "building";
  const live = isLive(status?.container.state);
  const hasWeb = !!lab.primary_url;

  async function doAction(action: "build" | "start" | "stop") {
    setPending(action);
    setActionError(null);
    try {
      const res = await authFetch(`/labs/${lab.id}/${action}`, { method: "POST" });
      if (!res.ok) {
        // THE "aren't spinning up" FIX: surface the failure instead of silently
        // doing nothing.
        setActionError(await readError(res));
        return;
      }
      flash(
        action === "build"
          ? "Build started…"
          : action === "start"
            ? "Starting…"
            : "Stopped",
      );
      await onRefresh();
    } catch (e) {
      setActionError(errString(e));
    } finally {
      setPending(null);
    }
  }

  // Attach the lab to the active engagement (or create one named "Lab: <name>"
  // seeded with the lab URL when there's no active engagement yet).
  async function attach() {
    setPending("attach");
    setActionError(null);
    try {
      let engagementId = getActiveEngagementId();
      let created = false;
      if (!engagementId) {
        const fresh = await createEngagement({
          name: `Lab: ${lab.name}`,
          scope: lab.primary_url ? [lab.primary_url] : [],
          exclusions: [],
          notes: "Auto-created when attaching a lab.",
        });
        engagementId = fresh.id;
        setActiveEngagementId(fresh.id);
        created = true;
      }
      const res = await authFetch(`/labs/${lab.id}/attach`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ engagement_id: engagementId }),
      });
      if (!res.ok) {
        setActionError(await readError(res));
        return;
      }
      flash(
        created
          ? `Created engagement “Lab: ${lab.name}” and attached.`
          : "Attached to the active engagement.",
      );
    } catch (e) {
      setActionError(errString(e));
    } finally {
      setPending(null);
    }
  }

  function openInBrowser() {
    if (lab.primary_url) window.open(lab.primary_url, "_blank", "noopener");
  }

  // Map a suggested step's route → tool id and hand it to the shell.
  function runStep(step: SuggestedStep) {
    const toolId = ROUTE_TO_TOOL[step.route];
    if (!toolId) return; // unknown route — chip is rendered disabled, but guard anyway
    emit("openTool", { toolId });
  }

  const steps = lab.suggested_steps.filter((s) => ROUTE_TO_TOOL[s.route]);

  return (
    <GlassCard glowOnHover className="flex flex-col gap-3 p-4">
      {/* Header */}
      <div className="flex items-start gap-3">
        <StatusDot color={dotColor(status)} static={!live && !building} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-bold text-ink-primary">{lab.name}</h3>
            <span
              className={`rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-widest ${categoryClasses(
                lab.category,
              )}`}
            >
              {lab.category || "Lab"}
            </span>
            <span className="font-mono text-[10px] uppercase tracking-widest text-ink-dim">
              {stateLabel(status)}
            </span>
          </div>
          <p className="mt-1 text-[12px] leading-snug text-ink-muted">{lab.summary}</p>
        </div>
      </div>

      {/* Meta */}
      <div className="flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] text-ink-dim">
        <span>{lab.image_tag}</span>
        {hasWeb ? (
          <a
            href={lab.primary_url}
            target="_blank"
            rel="noreferrer"
            className="text-accent hover:underline"
          >
            → {lab.primary_url}
          </a>
        ) : (
          <span>(no web port)</span>
        )}
        {lab.default_creds && <span>creds: {lab.default_creds}</span>}
      </div>

      {/* Actions */}
      <div className="flex flex-wrap gap-2">
        <Button
          variant="solid"
          size="sm"
          loading={pending === "build" || building}
          disabled={!runtimeOk || pending !== null || building}
          onClick={() => doAction("build")}
        >
          {building ? "Building…" : "Build"}
        </Button>
        <Button
          variant="glow"
          size="sm"
          loading={pending === "start"}
          disabled={!runtimeOk || pending !== null || live}
          onClick={() => doAction("start")}
        >
          {pending === "start" ? "Starting…" : "Start"}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          loading={pending === "stop"}
          disabled={pending !== null || !live}
          onClick={() => doAction("stop")}
        >
          Stop
        </Button>
        {hasWeb && (
          <Button
            variant="ghost"
            size="sm"
            disabled={!live}
            onClick={openInBrowser}
            title={live ? "Open the lab in your browser" : "Start the lab first"}
          >
            Open ↗
          </Button>
        )}
        <Button
          variant="ghost"
          size="sm"
          loading={pending === "attach"}
          disabled={pending !== null}
          onClick={attach}
          title={
            activeEngagementId
              ? "Attach this lab to the active engagement (adds its URL to scope)"
              : "No engagement yet — creates one named “Lab: …” with this lab in scope"
          }
        >
          {activeEngagementId ? "Attach to engagement" : "Start engagement with this lab"}
        </Button>
      </div>

      {/* Notice + error surfaces */}
      {notice && (
        <div className="rounded border border-accent/40 bg-accent/10 px-3 py-1.5 text-[11px] text-accent">
          {notice}
        </div>
      )}
      {(actionError || status?.build_status === "error") && (
        <InlineError
          message={
            actionError ?? status?.build_error ?? "Build failed — check the runtime."
          }
          onRetry={actionError ? undefined : undefined}
          onDismiss={() => setActionError(null)}
        />
      )}

      {/* Suggested steps */}
      {steps.length > 0 && (
        <div className="border-t border-divider pt-3">
          <div className="mb-2 text-[10px] uppercase tracking-widest text-ink-dim">
            Suggested next steps
          </div>
          <div className="flex flex-wrap gap-2">
            {steps.map((s) => (
              <button
                key={`${s.route}:${s.label}`}
                onClick={() => runStep(s)}
                disabled={!live}
                title={
                  live
                    ? s.description || `Open ${s.label}`
                    : "Start the lab to enable this step"
                }
                className="group rounded border border-divider bg-bg-card px-2.5 py-1 text-left text-[11px] transition hover:border-accent/60 hover:bg-accent/5 disabled:cursor-not-allowed disabled:opacity-50"
              >
                <span className="font-semibold text-ink-primary group-hover:text-accent">
                  {s.label}
                </span>
                <span className="ml-1.5 font-mono text-[10px] text-ink-dim">
                  → {ROUTE_TO_TOOL[s.route]}
                </span>
              </button>
            ))}
          </div>
        </div>
      )}
    </GlassCard>
  );
}

// ── Inline error ─────────────────────────────────────────────────────────────

function InlineError({
  message,
  onRetry,
  onDismiss,
}: {
  message: string;
  onRetry?: () => void;
  onDismiss?: () => void;
}) {
  return (
    <div className="flex items-start gap-3 rounded border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">
      <span className="flex-1 font-mono leading-snug">{message}</span>
      {onRetry && (
        <button
          onClick={onRetry}
          className="shrink-0 text-[11px] font-bold uppercase tracking-wider text-danger/90 hover:text-danger"
        >
          Retry
        </button>
      )}
      {onDismiss && (
        <button
          onClick={onDismiss}
          aria-label="Dismiss"
          className="shrink-0 text-lg leading-none text-danger/80 hover:text-danger"
        >
          ×
        </button>
      )}
    </div>
  );
}
