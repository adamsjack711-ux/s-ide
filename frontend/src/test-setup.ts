// Vitest setup. happy-dom doesn't ship a localStorage here, but a lot of the
// app persists through it (themes, accent, view modes, engagement). Provide a
// minimal in-memory shim so persistence paths are testable.
class MemStorage {
  private m = new Map<string, string>();
  get length() { return this.m.size; }
  key(i: number) { return [...this.m.keys()][i] ?? null; }
  getItem(k: string) { return this.m.has(k) ? this.m.get(k)! : null; }
  setItem(k: string, v: string) { this.m.set(k, String(v)); }
  removeItem(k: string) { this.m.delete(k); }
  clear() { this.m.clear(); }
}

if (typeof (globalThis as any).localStorage === "undefined") {
  const store = new MemStorage();
  (globalThis as any).localStorage = store;
  if ((globalThis as any).window) (globalThis as any).window.localStorage = store;
}

export {};
