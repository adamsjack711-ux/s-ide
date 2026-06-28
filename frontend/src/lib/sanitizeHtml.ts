// Tiny allow-list HTML sanitizer for third-party HTML snippets (e.g. HIBP
// breach descriptions). Browser-only — uses DOMParser. Returns a sanitized
// HTML string safe to feed into dangerouslySetInnerHTML.
//
// Keep the allow-list intentionally narrow. If we ever need more tags,
// add them deliberately rather than expanding wildcards.

const ALLOWED_TAGS = new Set([
  "P", "BR", "A", "STRONG", "EM", "B", "I", "UL", "OL", "LI", "CODE",
]);

// On <a>, only href is allowed, and only with http/https/mailto schemes.
function sanitizeAnchorAttrs(el: Element): void {
  const href = el.getAttribute("href") ?? "";
  // Strip all attributes first, then re-add href if it's safe.
  for (const attr of Array.from(el.attributes)) {
    el.removeAttribute(attr.name);
  }
  let safe = "";
  try {
    const u = new URL(href, "https://example.invalid/");
    if (u.protocol === "http:" || u.protocol === "https:" || u.protocol === "mailto:") {
      safe = u.toString();
    }
  } catch {
    /* invalid URL — drop */
  }
  if (safe) {
    el.setAttribute("href", safe);
    el.setAttribute("rel", "noopener noreferrer");
    el.setAttribute("target", "_blank");
  }
}

function walk(node: Node): void {
  // Iterate over a snapshot — we may remove/replace children during walk.
  for (const child of Array.from(node.childNodes)) {
    if (child.nodeType === Node.ELEMENT_NODE) {
      const el = child as Element;
      if (!ALLOWED_TAGS.has(el.tagName)) {
        // Unwrap: replace the element with its text content. This drops
        // <script>, <iframe>, <img onerror>, on* handlers, style, etc.
        const text = el.textContent ?? "";
        el.replaceWith(document.createTextNode(text));
        continue;
      }
      if (el.tagName === "A") {
        sanitizeAnchorAttrs(el);
      } else {
        // For other allowed tags, strip every attribute.
        for (const attr of Array.from(el.attributes)) {
          el.removeAttribute(attr.name);
        }
      }
      walk(el);
    }
    // Text and comment nodes: text is fine, comments are dropped by DOMParser.
  }
}

export function sanitizeHtml(input: string): string {
  if (!input) return "";
  const doc = new DOMParser().parseFromString(`<div>${input}</div>`, "text/html");
  const root = doc.body.firstElementChild;
  if (!root) return "";
  walk(root);
  return root.innerHTML;
}
