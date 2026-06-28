/**
 * Codebase Scan — local regex-based SAST.
 *
 * One http-transport tool: point at a local source directory and the backend
 * walks it with language-agnostic SAST patterns, surfacing the design's "SAST"
 * finding source (hardcoded secrets, SQLi, command injection, XSS sinks,
 * insecure deserialization, weak crypto, path traversal).
 */
import { authFetch } from "../../api";
import type { ResultRow, ToolDescriptor } from "./types";

const CODESCAN: ToolDescriptor = {
  id: "codescan",
  label: "Codebase Scan",
  group: "Code",
  blurb: "Local SAST — regex scan of a source directory for hardcoded secrets, SQLi, command injection, XSS, and more.",
  tier: 1,
  transport: "http",
  mode: "passive",
  fields: [
    { name: "path", label: "Codebase path", type: "path", placeholder: "/Users/you/project", required: true },
  ],
  columns: ["Severity", "Type", "Location", "Title"],
  run: (v) =>
    authFetch("/codescan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: v.path.trim() }),
    }).then((r) => r.json()),
  toRows: (json): ResultRow[] =>
    (json?.findings || []).map((f: any) => ({
      cols: [f.severity, f.type, `${f.file}:${f.line}`, f.title],
      level: f.severity === "critical" || f.severity === "high" ? "error" : "info",
    })),
  doneText: (json) => `${(json?.findings || []).length} findings · ${json?.scanned_files ?? 0} files`,
};

export const CODESCAN_TOOLS: ToolDescriptor[] = [CODESCAN];
