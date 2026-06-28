// SettingsView — the s-ide settings surface.
//
// Ported from HackingPal's Settings page, leaning hard on performative-ui:
//   GlassCard for every section, GradientText + EyebrowPill for headers,
//   Button for actions, StatusDot for live status, Sparkle for accents.
//
// Sections:
//   1. Appearance — theme picker (dark / light / system) via useTheme.
//   2. AI / Copilot — provider + key status, key paste field, model picker,
//      system-prompt editor (when editable).
//   3. Effects — Dopamine mood / intensity / whimsy + presets + effect gallery.
//   4. Capabilities — embeds the existing shell/CapabilitiesPanel verbatim.
//
// This file owns NO backend contracts of its own: every call routes through
// the existing api.ts client fns (fetchChatConfig / fetchChatSettings /
// updateChatSettings / fetchApiKeyStatus / setApiKey / deleteApiKey). Theme,
// dopamine, and capability state all come from their lib modules.

import { useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";
import {
  Button,
  EyebrowPill,
  GlassCard,
  GradientText,
  Sparkle,
  StatusDot,
  WibblingSpinner,
} from "performative-ui";

import { useTheme, type ThemeChoice } from "../lib/theme";
import { ACCENTS, useAccent } from "../lib/accent";
import {
  fetchChatConfig,
  fetchChatSettings,
  updateChatSettings,
  fetchApiKeyStatus,
  setApiKey,
  deleteApiKey,
  type ChatConfig,
  type ChatSettings,
  type ApiKeyStatus,
} from "../api";
import {
  DOPAMINE_DEFAULTS,
  DOPAMINE_PRESETS,
  getSettings as getDopamineSettings,
  setSettings as setDopamineSettings,
  resetSettings as resetDopamineSettings,
  playNamed,
  pulse,
  celebrateBig,
  inkConfirm,
  radarSweep,
  failStamp,
  type DopamineSettings,
  type DopamineMood,
  type EffectName,
} from "../lib/dopamine";
import CapabilitiesPanel from "../shell/CapabilitiesPanel";

// CSS-var colors used by StatusDot (live, animated pulse).
const C_SUCCESS = "rgb(var(--success-rgb))";
const C_PHOS = "rgb(var(--phos-rgb))";
const C_DANGER = "rgb(var(--danger-rgb))";
const C_DIM = "rgb(var(--ink-dim-rgb))";
const C_ACCENT = "rgb(var(--accent-rgb))";

export default function SettingsView() {
  return (
    <div className="h-full overflow-y-auto bg-bg-base">
      <header className="border-b border-divider px-6 pt-5 pb-4">
        <EyebrowPill icon={false} className="text-[10px]">
          s-ide
        </EyebrowPill>
        <h1 className="mt-2 flex items-center gap-2 text-2xl font-bold tracking-tight">
          <GradientText>Settings</GradientText>
          <Sparkle />
        </h1>
        <p className="mt-1 max-w-2xl text-[12px] text-ink-muted">
          Appearance, the AI copilot, visual effects, and tool capabilities.
          Keys live in the OS keychain — never written to disk.
        </p>
      </header>

      <div className="mx-auto max-w-3xl space-y-5 p-6">
        <AppearanceSection />
        <CopilotSection />
        <EffectsSection />
        <CapabilitiesSection />
      </div>
    </div>
  );
}

// ── Shared section shell ──────────────────────────────────────────────────

function Section({
  eyebrow,
  title,
  hint,
  status,
  children,
}: {
  eyebrow: string;
  title: string;
  hint: string;
  status?: ReactNode;
  children: ReactNode;
}) {
  return (
    <GlassCard className="p-0" glowOnHover>
      <header className="flex items-start gap-3 border-b border-divider px-5 py-3.5">
        <div className="flex-1">
          <EyebrowPill icon={false} className="text-[10px]">
            {eyebrow}
          </EyebrowPill>
          <h2 className="mt-1.5 text-[15px] font-bold text-ink-primary">
            <GradientText static>{title}</GradientText>
          </h2>
          <p className="mt-0.5 text-[11px] text-ink-dim">{hint}</p>
        </div>
        {status && <div className="shrink-0 pt-1">{status}</div>}
      </header>
      <div className="p-5">{children}</div>
    </GlassCard>
  );
}

// ── 1. Appearance ─────────────────────────────────────────────────────────

function AppearanceSection() {
  const theme = useTheme();
  const [accent, setAccent] = useAccent();
  const choices: { id: ThemeChoice; label: string; hint: string }[] = [
    { id: "midnight", label: "Midnight", hint: "the default" },
    { id: "graphite", label: "Graphite", hint: "" },
    { id: "light", label: "Light", hint: "" },
    { id: "system", label: "System", hint: `now ${theme.resolved}` },
  ];

  return (
    <Section
      eyebrow="Appearance"
      title="Theme & accent"
      hint="Persisted to localStorage. System follows your OS preference live."
      status={
        <span className="inline-flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-ink-dim">
          <StatusDot color="var(--accent)" static />
          {theme.resolved}
        </span>
      }
    >
      <div className="flex flex-wrap gap-2">
        {choices.map((c) => {
          const active = theme.choice === c.id;
          return (
            <Button
              key={c.id}
              variant={active ? "solid" : "ghost"}
              size="sm"
              onClick={() => theme.setChoice(c.id)}
            >
              {c.label}
              {c.hint && <span className="ml-1.5 text-[10px] opacity-70">{c.hint}</span>}
            </Button>
          );
        })}
      </div>

      <div className="mt-4">
        <div className="mb-2 font-mono text-[10.5px] uppercase tracking-wider text-ink-dim">Accent</div>
        <div className="flex items-center gap-3">
          {ACCENTS.map((a) => {
            const on = accent.toLowerCase() === a.hex.toLowerCase();
            return (
              <button
                key={a.hex}
                title={a.name}
                onClick={() => setAccent(a.hex)}
                className="h-7 w-7 rounded-full transition-shadow"
                style={{ background: a.hex, boxShadow: on ? `0 0 0 2px var(--bg-card), 0 0 0 4px ${a.hex}` : "none" }}
              />
            );
          })}
          <span className="ml-1 text-xs text-ink-muted">
            {ACCENTS.find((a) => a.hex.toLowerCase() === accent.toLowerCase())?.name ?? "Custom"}
          </span>
        </div>
      </div>
    </Section>
  );
}

// ── 2. AI / Copilot ───────────────────────────────────────────────────────

const MODEL_LABELS: Record<string, { label: string; hint: string }> = {
  "claude-opus-4-7": { label: "Opus 4.7", hint: "Smartest, slowest, priciest." },
  "claude-sonnet-4-6": {
    label: "Sonnet 4.6",
    hint: "Recommended default — fast + plenty smart.",
  },
  "claude-haiku-4-5-20251001": {
    label: "Haiku 4.5",
    hint: "Fastest + cheapest. Weaker multi-step reasoning.",
  },
};

function CopilotSection() {
  const [config, setConfig] = useState<ChatConfig | null>(null);
  const [keyStatus, setKeyStatus] = useState<ApiKeyStatus | null>(null);
  const [settings, setSettings] = useState<ChatSettings | null>(null);

  const [keyInput, setKeyInput] = useState("");
  const [prompt, setPrompt] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [flash, setFlash] = useState("");

  const refresh = useCallback(async () => {
    const [c, k, s] = await Promise.all([
      fetchChatConfig().catch(() => null),
      fetchApiKeyStatus().catch(() => ({ present: false }) as ApiKeyStatus),
      fetchChatSettings().catch(() => null),
    ]);
    setConfig(c);
    setKeyStatus(k);
    if (s) {
      setSettings(s);
      setPrompt(s.system_prompt);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  function flashFor(msg: string) {
    setFlash(msg);
    window.setTimeout(() => setFlash(""), 2000);
  }

  async function saveKey() {
    const k = keyInput.trim();
    if (!k) return;
    setBusy(true);
    setError("");
    try {
      const st = await setApiKey(k);
      setKeyStatus(st);
      setKeyInput("");
      void fetchChatConfig().then(setConfig).catch(() => {});
      flashFor("API key saved to keychain.");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function removeKey() {
    if (!confirm("Remove the saved Anthropic API key from the keychain?")) return;
    setBusy(true);
    setError("");
    try {
      const st = await deleteApiKey();
      setKeyStatus(st);
      void fetchChatConfig().then(setConfig).catch(() => {});
      flashFor("API key removed.");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function pickModel(m: string) {
    if (!settings || m === settings.model) return;
    setBusy(true);
    setError("");
    try {
      const updated = await updateChatSettings({ model: m });
      setSettings(updated);
      flashFor("Model updated.");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function savePrompt() {
    if (!settings) return;
    setBusy(true);
    setError("");
    try {
      const updated = await updateChatSettings({ system_prompt: prompt });
      setSettings(updated);
      setPrompt(updated.system_prompt);
      flashFor("System prompt saved.");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  // Provider/usability status dot.
  const usable = !!config?.usable;
  const providerLabel =
    config?.provider === "claude-cli"
      ? "Claude CLI"
      : config?.provider === "anthropic"
        ? "Anthropic API"
        : "—";
  const dotColor = usable ? C_SUCCESS : C_DANGER;
  const statusText = usable ? "Ready" : "Not configured";

  const promptDirty = !!settings && settings.system_prompt !== prompt;

  return (
    <Section
      eyebrow="AI · Copilot"
      title="Assistant"
      hint="Provider, API key, model, and system prompt for the in-app copilot."
      status={
        <span className="inline-flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-ink-dim">
          <StatusDot color={dotColor} static={!usable} />
          {statusText}
        </span>
      }
    >
      <div className="space-y-5">
        {/* Provider + key status */}
        <div>
          <Label>Provider</Label>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px]">
            <span className="text-ink-primary">{providerLabel}</span>
            <span className="inline-flex items-center gap-1.5 text-ink-muted">
              <StatusDot
                color={config?.key_present ? C_PHOS : C_DIM}
                static={!config?.key_present}
              />
              {config?.key_present || keyStatus?.present
                ? "key present"
                : "no key"}
              {keyStatus?.present && keyStatus.last4 && (
                <code className="text-accent">…{keyStatus.last4}</code>
              )}
            </span>
            {config?.cli_present && (
              <span className="text-ink-dim">CLI available</span>
            )}
          </div>
        </div>

        {/* Key paste / remove */}
        <div>
          <Label>Anthropic API key</Label>
          {keyStatus?.present ? (
            <div className="flex items-center gap-3">
              <span className="inline-flex items-center gap-2 text-[12px] text-ink-primary">
                <StatusDot color={C_PHOS} static />
                Configured
                {keyStatus.last4 && (
                  <code className="text-accent">…{keyStatus.last4}</code>
                )}
              </span>
              <Button
                variant="ghost"
                size="sm"
                className="ml-auto"
                loading={busy}
                onClick={() => void removeKey()}
              >
                Remove
              </Button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <input
                type="password"
                value={keyInput}
                onChange={(e) => setKeyInput(e.target.value)}
                placeholder="sk-ant-…"
                disabled={busy}
                spellCheck={false}
                autoComplete="off"
                className="flex-1 rounded border border-divider bg-bg-base px-2.5 py-1.5
                           font-mono text-[12px] text-ink-primary focus:border-accent
                           focus:outline-none"
              />
              <Button
                variant="solid"
                size="sm"
                loading={busy}
                disabled={!keyInput.trim()}
                onClick={() => void saveKey()}
              >
                Save
              </Button>
            </div>
          )}
          <p className="mt-1.5 text-[10px] text-ink-dim">
            Stored in the OS keychain via <code>/settings/api-key</code>. Paste
            your own key here.
          </p>
        </div>

        {/* Model picker */}
        {settings ? (
          <div>
            <Label>Model</Label>
            <div className="flex flex-col gap-1.5">
              {settings.available_models.map((m) => {
                const meta = MODEL_LABELS[m] ?? { label: m, hint: "" };
                const active = settings.model === m;
                return (
                  <button
                    key={m}
                    onClick={() => void pickModel(m)}
                    disabled={busy}
                    className={
                      "flex items-start gap-2.5 rounded border px-3 py-2 text-left transition " +
                      (active
                        ? "border-accent bg-accent/10"
                        : "border-divider bg-bg-card hover:border-ink-muted")
                    }
                  >
                    <StatusDot
                      color={active ? C_ACCENT : C_DIM}
                      static={!active}
                    />
                    <span className="flex-1">
                      <span className="text-[12px] font-bold text-ink-primary">
                        {meta.label}
                        <code className="ml-2 text-[10px] font-normal text-ink-dim">
                          {m}
                        </code>
                      </span>
                      {meta.hint && (
                        <span className="mt-0.5 block text-[10px] text-ink-muted">
                          {meta.hint}
                        </span>
                      )}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-2 text-[11px] text-ink-dim">
            <WibblingSpinner />
          </div>
        )}

        {/* System prompt */}
        {settings && (
          <div>
            <div className="mb-1.5 flex items-center gap-2">
              <Label inline>System prompt</Label>
              {settings.system_prompt_path && (
                <code className="truncate text-[10px] text-ink-dim">
                  {settings.system_prompt_path}
                </code>
              )}
            </div>
            {settings.system_prompt_editable ? (
              <>
                <textarea
                  value={prompt}
                  onChange={(e) => setPrompt(e.target.value)}
                  rows={9}
                  disabled={busy}
                  spellCheck={false}
                  className="w-full resize-y rounded border border-divider bg-bg-base
                             px-2.5 py-2 font-mono text-[11px] leading-relaxed
                             text-ink-primary focus:border-accent focus:outline-none"
                />
                <div className="mt-2 flex items-center gap-2">
                  <Button
                    variant="solid"
                    size="sm"
                    loading={busy}
                    disabled={!promptDirty}
                    onClick={() => void savePrompt()}
                  >
                    Save prompt
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={busy || !promptDirty}
                    onClick={() => setPrompt(settings.system_prompt)}
                  >
                    Revert
                  </Button>
                  <span className="ml-auto text-[10px] text-ink-dim">
                    {prompt.length.toLocaleString()} chars
                  </span>
                </div>
              </>
            ) : (
              <div className="rounded border border-amber/30 bg-amber/10 p-2 text-[11px] text-amber">
                System prompt is read-only — an environment override is set.
              </div>
            )}
          </div>
        )}

        {/* Flash + errors */}
        {flash && (
          <div className="flex items-center gap-1.5 text-[11px] text-success">
            <Sparkle solid /> {flash}
          </div>
        )}
        {error && <div className="text-[11px] text-danger">⚠ {error}</div>}
      </div>
    </Section>
  );
}

// ── 3. Effects (Dopamine) ─────────────────────────────────────────────────

const MOODS: { id: DopamineMood; label: string; hint: string }[] = [
  { id: "serene", label: "Serene", hint: "quiet, cool" },
  { id: "celebratory", label: "Celebratory", hint: "warm, bright" },
  { id: "electric", label: "Electric", hint: "violet (default)" },
];

// Effect gallery: each tile fires its effect anchored to the tile itself.
type EffectTile = {
  id: string;
  label: string;
  hint: string;
  fire: (el: HTMLElement) => Promise<void>;
};

const NAMED_EFFECTS: { name: EffectName; hint: string }[] = [
  { name: "solarbloom", hint: "scan-complete bloom" },
  { name: "ripple", hint: "radar wavefronts" },
  { name: "inkstroke", hint: "auth ink stroke" },
  { name: "confetti", hint: "celebratory burst" },
  { name: "heartburst", hint: "warm burst" },
  { name: "lightning", hint: "electric arc" },
  { name: "comic", hint: "BAM! impact" },
  { name: "fail", hint: "error stamp" },
];

const GALLERY: EffectTile[] = [
  ...NAMED_EFFECTS.map<EffectTile>((e) => ({
    id: `play:${e.name}`,
    label: e.name,
    hint: e.hint,
    fire: (el) => playNamed(e.name, el),
  })),
  { id: "h:pulse", label: "pulse()", hint: "celebrate", fire: (el) => pulse(el) },
  {
    id: "h:celebrateBig",
    label: "celebrateBig()",
    hint: "milestone (1.5×)",
    fire: (el) => celebrateBig(el),
  },
  {
    id: "h:inkConfirm",
    label: "inkConfirm()",
    hint: "checkbox confirm",
    fire: (el) => inkConfirm(el),
  },
  {
    id: "h:radarSweep",
    label: "radarSweep()",
    hint: "scan start",
    fire: (el) => radarSweep(el),
  },
  {
    id: "h:failStamp",
    label: "failStamp()",
    hint: "error",
    fire: (el) => failStamp(el),
  },
];

/** Identify which preset (if any) the current settings exactly match. */
function detectPreset(s: DopamineSettings): string | null {
  for (const p of DOPAMINE_PRESETS) {
    const merged: DopamineSettings = { ...DOPAMINE_DEFAULTS, ...p.patch };
    if (merged.enabled !== s.enabled) continue;
    if (!merged.enabled) return p.id;
    if (Math.abs(merged.intensity - s.intensity) > 0.001) continue;
    if (Math.abs(merged.whimsy - s.whimsy) > 0.001) continue;
    return p.id;
  }
  return null;
}

function EffectsSection() {
  const [settings, setSettings] = useState<DopamineSettings>(() =>
    getDopamineSettings(),
  );
  const [presetId, setPresetId] = useState<string | null>(() =>
    detectPreset(getDopamineSettings()),
  );
  const [firing, setFiring] = useState<string | null>(null);

  // Stay in sync if another part of the app changes dopamine settings.
  useEffect(() => {
    function onChange(e: Event) {
      const next = (e as CustomEvent<DopamineSettings>).detail;
      if (next) {
        setSettings(next);
        setPresetId(detectPreset(next));
      }
    }
    window.addEventListener("mhp:dopamine-changed", onChange);
    return () => window.removeEventListener("mhp:dopamine-changed", onChange);
  }, []);

  function patch(p: Partial<DopamineSettings>) {
    const next = setDopamineSettings(p);
    setSettings(next);
    setPresetId(detectPreset(next));
  }

  function applyPreset(id: string) {
    const preset = DOPAMINE_PRESETS.find((p) => p.id === id);
    if (!preset) return;
    const next = setDopamineSettings(preset.patch);
    setSettings(next);
    setPresetId(id);
  }

  function reset() {
    const next = resetDopamineSettings();
    setSettings(next);
    setPresetId(detectPreset(next));
  }

  async function fire(tile: EffectTile, el: HTMLElement) {
    setFiring(tile.id);
    try {
      await tile.fire(el);
    } catch {
      /* effects are best-effort */
    } finally {
      window.setTimeout(
        () => setFiring((cur) => (cur === tile.id ? null : cur)),
        400,
      );
    }
  }

  const off = !settings.enabled;

  return (
    <Section
      eyebrow="Effects"
      title="Dopamine"
      hint="Visual flourishes on scan start / complete / auth. Respects reduced-motion. Persists to localStorage."
      status={
        <span className="inline-flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-ink-dim">
          <StatusDot color={off ? C_DIM : C_ACCENT} static={off} />
          {off ? "off" : "on"}
        </span>
      }
    >
      {/* Master toggle */}
      <div className="mb-4 flex items-center justify-between gap-4 border-b border-divider pb-4">
        <div>
          <div className="text-[12px] font-bold text-ink-primary">
            {settings.enabled ? "Effects enabled" : "Effects disabled"}
          </div>
          <p className="mt-0.5 max-w-md text-[11px] text-ink-dim">
            Master kill-switch. Reduced-motion always wins regardless.
          </p>
        </div>
        <Button
          variant={settings.enabled ? "solid" : "ghost"}
          size="sm"
          onClick={() => patch({ enabled: !settings.enabled })}
        >
          {settings.enabled ? "On" : "Off"}
        </Button>
      </div>

      <div className={off ? "pointer-events-none opacity-40" : ""}>
        {/* Presets */}
        <Label>Vibe preset</Label>
        <div className="mb-5 flex flex-wrap gap-2">
          {DOPAMINE_PRESETS.map((p) => (
            <Button
              key={p.id}
              variant={presetId === p.id ? "solid" : "ghost"}
              size="sm"
              title={p.hint}
              onClick={() => applyPreset(p.id)}
            >
              {p.label}
              <span className="ml-1.5 text-[10px] opacity-70">{p.hint}</span>
            </Button>
          ))}
        </div>

        {/* Mood */}
        <Label>Mood</Label>
        <div className="mb-5 flex flex-wrap gap-2">
          {MOODS.map((m) => (
            <Button
              key={m.id}
              variant={settings.mood === m.id ? "solid" : "ghost"}
              size="sm"
              onClick={() => patch({ mood: m.id })}
            >
              {m.label}
              <span className="ml-1.5 text-[10px] opacity-70">{m.hint}</span>
            </Button>
          ))}
        </div>

        {/* Sliders */}
        <div className="mb-5 space-y-4">
          <Slider
            label="Intensity"
            hint="energy — bigger, brighter"
            value={settings.intensity}
            onChange={(v) => patch({ intensity: v })}
          />
          <Slider
            label="Whimsy"
            hint="variation per fire"
            value={settings.whimsy}
            onChange={(v) => patch({ whimsy: v })}
          />
        </div>

        {/* Gallery */}
        <Label>Gallery — click a tile to fire it</Label>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 md:grid-cols-4">
          {GALLERY.map((tile) => (
            <button
              key={tile.id}
              onClick={(e) => void fire(tile, e.currentTarget)}
              disabled={firing === tile.id}
              className="group rounded-md border border-divider bg-bg-card px-3 py-2.5
                         text-left transition hover:border-accent disabled:opacity-60"
            >
              <div className="flex items-center gap-1.5 font-mono text-[12px] font-bold
                              text-ink-primary group-hover:text-accent">
                {firing === tile.id ? (
                  <>
                    <Sparkle solid /> firing…
                  </>
                ) : (
                  tile.label
                )}
              </div>
              <div className="mt-0.5 truncate text-[10px] text-ink-dim">
                {tile.hint}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Reset */}
      <div className="mt-4 flex items-center justify-between border-t border-divider pt-4">
        <code className="text-[10px] text-ink-dim">localStorage["mhp:dopamine"]</code>
        <Button
          variant="ghost"
          size="sm"
          title={`Reset to ${DOPAMINE_DEFAULTS.mood} · ${DOPAMINE_DEFAULTS.intensity} / ${DOPAMINE_DEFAULTS.whimsy}`}
          onClick={reset}
        >
          Reset to defaults
        </Button>
      </div>
    </Section>
  );
}

function Slider({
  label,
  hint,
  value,
  onChange,
}: {
  label: string;
  hint: string;
  value: number;
  onChange: (v: number) => void;
}) {
  const pct = Math.round(value * 100);
  return (
    <label className="block">
      <div className="mb-1 flex items-baseline gap-2">
        <span className="text-[11px] font-bold uppercase tracking-widest text-ink-muted">
          {label}
        </span>
        <span className="text-[10px] text-ink-dim">{hint}</span>
        <span className="flex-1" />
        <span className="font-mono text-[11px] tabular-nums text-accent">
          {value.toFixed(2)} · {pct}%
        </span>
      </div>
      <input
        type="range"
        min={0}
        max={1}
        step={0.05}
        value={value}
        onChange={(e) => onChange(parseFloat(e.target.value))}
        className="w-full accent-accent"
      />
    </label>
  );
}

// ── 4. Capabilities ───────────────────────────────────────────────────────

function CapabilitiesSection() {
  // Embed the existing panel. It manages its own scroll + bg-sidebar; we cap
  // its height and round the corners so it reads as a section rather than a
  // full-height sidebar.
  return (
    <Section
      eyebrow="Capabilities"
      title="Tool gating"
      hint="Privileged, external-setup, and intrusive tool groups stay off until enabled. Scope, authorization, and audit remain enforced server-side."
    >
      <div className="max-h-[420px] overflow-hidden rounded-md border border-divider">
        <CapabilitiesPanel />
      </div>
    </Section>
  );
}

// ── tiny label helper ─────────────────────────────────────────────────────

function Label({
  children,
  inline,
}: {
  children: ReactNode;
  inline?: boolean;
}) {
  return (
    <div
      className={
        "text-[10px] font-bold uppercase tracking-widest text-ink-dim " +
        (inline ? "" : "mb-2")
      }
    >
      {children}
    </div>
  );
}
