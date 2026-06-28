// Centralised URL allow-list helper.
//
// Every dynamic <a href> in the app must route through this. A naïve
// `<a href={apiData.url}>` lets a malicious target server (or a teammate
// attaching evidence with `content="javascript:..."`) ship a script URL
// that XSSes the renderer — and the renderer holds the auth token that
// authorises /terminal/exec.
//
// Usage:
//   const href = safeHttpUrl(d.url);
//   return href
//     ? <a href={href} target="_blank" rel="noopener noreferrer">{d.title}</a>
//     : <span>{d.title}</span>;
//
// http/https only by default. Pass `{ mailto: true }` for contact links.

type Options = { mailto?: boolean };

export function safeHttpUrl(raw: unknown, opts: Options = {}): string | undefined {
  if (typeof raw !== "string" || !raw) return undefined;
  let parsed: URL;
  try {
    parsed = new URL(raw, "https://example.invalid/");
  } catch {
    return undefined;
  }
  if (parsed.protocol === "http:" || parsed.protocol === "https:") {
    return parsed.toString();
  }
  if (opts.mailto && parsed.protocol === "mailto:") {
    return parsed.toString();
  }
  return undefined;
}
