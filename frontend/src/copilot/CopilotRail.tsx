import { useEffect, useRef, useState } from "react";
import { Sparkle, TokenStream } from "performative-ui";
import MethodReconstruction from "./MethodReconstruction";
import { authFetch, fetchChatConfig, suggestChecks, type ChatConfig, type SuggestedCheck } from "../api";
import { snapshot } from "../lib/sessionLog";
import { confirmStepWhy } from "../lib/retest";
import { notify } from "../shell/toast";
import { toolById, TOOLS } from "../shell/tools";
import { emit, on } from "../shell/bus";

type Msg = { role: "user" | "assistant"; content: string };

/** Map a suggested check's tool/nav id onto a slim-set tool id, if we expose it. */
function resolveTool(c: SuggestedCheck): string | undefined {
  const direct = toolById(c.tool) ?? toolById(c.nav_id);
  if (direct) return direct.id;
  const alias: Record<string, string> = { dns: "dns_recon", ports: "port_scanner", httpx: "http_probe", "http-probe": "http_probe" };
  const id = alias[c.nav_id] ?? alias[c.tool];
  return id && toolById(id) ? id : TOOLS.find((t) => c.tool.includes(t.id) || t.id.includes(c.tool))?.id;
}

/**
 * The ambient copilot — a persistent right rail, not a chat bubble. Streams over
 * /chat/stream (SSE) with the session-log substrate as context, surfaces
 * "suggest checks" approve cards, and degrades to a Connect-AI state when no
 * provider (Anthropic key or Claude CLI) is detected.
 */
export default function CopilotRail({ onClose }: { onClose?: () => void }) {
  const [cfg, setCfg] = useState<ChatConfig | null>(null);
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [checks, setChecks] = useState<SuggestedCheck[]>([]);
  const [focusedFinding, setFocusedFinding] = useState<string | null>(null);
  const activePage = useRef("s-ide");
  const endRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    fetchChatConfig().then(setCfg).catch(() => setCfg({ usable: false } as ChatConfig));
  }, []);
  useEffect(() => on("openTool", ({ toolId }) => (activePage.current = toolById(toolId)?.label ?? toolId)), []);
  useEffect(() => on("focusFinding", ({ findingId }) => setFocusedFinding(findingId)), []);
  useEffect(() => endRef.current?.scrollIntoView({ block: "end" }), [messages, streaming]);

  async function send(override?: string) {
    const text = (override ?? input).trim();
    if (!text || streaming) return;
    const next: Msg[] = [...messages, { role: "user", content: text }];
    setMessages(next);
    setInput("");
    setStreaming(true);
    setMessages((m) => [...m, { role: "assistant", content: "" }]);

    try {
      const res = await authFetch("/chat/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: next, session_log: snapshot(), active_page: activePage.current }),
      });
      const reader = res.body?.getReader();
      if (!reader) throw new Error("no stream");
      const dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const parts = buf.split("\n\n");
        buf = parts.pop() ?? "";
        for (const part of parts) {
          const line = part.split("\n").find((l) => l.startsWith("data:"));
          if (!line) continue;
          const payload = line.slice(5).trim();
          if (!payload || payload === "[DONE]") continue;
          try {
            const ev = JSON.parse(payload);
            if (ev.type === "text_delta" && ev.text) {
              setMessages((m) => {
                const copy = [...m];
                copy[copy.length - 1] = { role: "assistant", content: copy[copy.length - 1].content + ev.text };
                return copy;
              });
            }
          } catch {
            /* keep-alive / non-JSON line */
          }
        }
      }
    } catch (e: any) {
      setMessages((m) => {
        const copy = [...m];
        copy[copy.length - 1] = { role: "assistant", content: `⚠ ${e?.message || "stream failed"}` };
        return copy;
      });
    } finally {
      setStreaming(false);
    }
  }

  async function suggest() {
    try {
      const r = await suggestChecks({
        messages: messages.map((m) => ({ role: m.role, content: m.content })),
        active_page: activePage.current,
      });
      setChecks(r.checks || []);
    } catch {
      setChecks([]);
    }
  }

  function approve(c: SuggestedCheck) {
    const id = resolveTool(c);
    if (id) emit("openTool", { toolId: id });
    setChecks((cs) => cs.filter((x) => x !== c));
  }

  return (
    <div className="flex h-full w-[360px] shrink-0 flex-col border-l border-divider bg-bg-card">
      {/* Header — sparkle + live pill (per design), close on the right. */}
      <div className="flex h-[46px] shrink-0 items-center gap-2 border-b border-divider px-3.5">
        <span className="flex text-accent">
          <Sparkle />
        </span>
        <span className="text-[calc(13px_*_var(--text-scale))] font-semibold text-ink-primary">S-IDE Copilot</span>
        {cfg?.usable ? (
          <span className="rounded-full bg-accent/[0.13] px-1.5 py-0.5 font-mono text-[calc(10px_*_var(--text-scale))] font-medium text-accent">
            {cfg.model ? cfg.model : "live"}
          </span>
        ) : null}
        <button onClick={onClose} title="Hide copilot" className="ml-auto flex text-ink-dim hover:text-ink-primary">
          ×
        </button>
      </div>

      {focusedFinding && (
        <div className="max-h-[55%] overflow-auto border-b border-divider">
          <div className="flex items-center justify-between bg-bg-base px-3.5 py-2 text-[calc(10px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">
            <span className="flex items-center gap-2 font-mono">
              <span className="h-[7px] w-[7px] rounded-full bg-danger" /> Investigation context
            </span>
            <button onClick={() => setFocusedFinding(null)} className="hover:text-ink-primary">close</button>
          </div>
          <MethodReconstruction
            findingId={focusedFinding}
            onConfirmWhy={(stepId, why) =>
              confirmStepWhy(focusedFinding, stepId, why)
                .then(() => notify({ kind: "success", message: "Rationale recorded" }))
                .catch((e: any) =>
                  notify({ kind: "error", message: e?.message || "failed to record rationale" }),
                )
            }
          />
        </div>
      )}

      {cfg && !cfg.usable ? (
        <div className="space-y-2 p-4 text-xs text-ink-muted">
          <div className="font-medium text-ink-primary">Connect AI</div>
          <p>Set an Anthropic API key in Settings, or sign into the <span className="font-mono">claude</span> CLI on your PATH.</p>
        </div>
      ) : (
        <>
          {/* Conversation — AI vs user bubbles, chips pinned under the last turn. */}
          <div className="flex min-h-0 flex-1 flex-col gap-3.5 overflow-auto px-3.5 py-4">
            {messages.map((m, i) => {
              const isUser = m.role === "user";
              const thinking = !isUser && i === messages.length - 1 && streaming && !m.content;
              return (
                <div key={i} className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
                  <div
                    className={
                      isUser
                        ? "max-w-[85%] whitespace-pre-wrap rounded-xl rounded-br-[3px] border border-accent/30 bg-accent/[0.16] px-3.5 py-2.5 text-[calc(12.5px_*_var(--text-scale))] leading-relaxed text-ink-primary"
                        : "max-w-[90%] whitespace-pre-wrap rounded-xl rounded-bl-[3px] border border-divider bg-bg-base px-3.5 py-2.5 text-[calc(12.5px_*_var(--text-scale))] leading-relaxed text-ink-primary"
                    }
                  >
                    {thinking ? <TokenStream text="thinking…" speedMs={[40, 90]} loop /> : m.content}
                  </div>
                </div>
              );
            })}

            {checks.length > 0 && (
              <div className="space-y-2">
                <div className="text-[calc(10px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">Suggested checks</div>
                {checks.map((c, i) => (
                  <div key={i} className="rounded-lg bg-bg-base p-2.5 ring-1 ring-divider">
                    <div className="text-xs font-medium text-ink-primary">{c.label}</div>
                    <div className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">{c.target} — {c.rationale}</div>
                    <div className="mt-2 flex gap-2">
                      <button onClick={() => approve(c)} className="rounded-md bg-accent px-2.5 py-1 text-[calc(11px_*_var(--text-scale))] font-semibold text-bg-base hover:brightness-110">Approve</button>
                      <button onClick={() => setChecks((cs) => cs.filter((x) => x !== c))} className="rounded-md px-2 py-1 text-[calc(11px_*_var(--text-scale))] text-ink-muted hover:text-ink-primary">Skip</button>
                    </div>
                  </div>
                ))}
              </div>
            )}
            <div ref={endRef} />
          </div>

          {/* Composer — "ask to fix" suggest action + bubble-style input. */}
          <div className="border-t border-divider px-3.5 py-3">
            <button
              onClick={suggest}
              disabled={streaming}
              className="mb-2 flex items-center gap-1.5 text-[calc(11px_*_var(--text-scale))] font-medium text-accent hover:underline disabled:opacity-50"
            >
              <span className="flex">
                <Sparkle />
              </span>
              Suggest next checks
            </button>
            <div className="flex items-center gap-2.5 rounded-[10px] border border-divider bg-bg-base px-3 py-2 focus-within:border-accent">
              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && send()}
                placeholder={cfg ? "Ask about this finding…" : "…"}
                disabled={streaming}
                className="flex-1 bg-transparent text-[calc(12.5px_*_var(--text-scale))] text-ink-primary outline-none placeholder:text-ink-dim"
              />
              <button
                onClick={() => send()}
                disabled={streaming}
                title="Send"
                className="flex text-accent hover:brightness-110 disabled:opacity-50"
              >
                ↩
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
