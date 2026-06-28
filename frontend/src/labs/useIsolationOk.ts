import { useEffect, useState } from "react";
import { authFetch } from "../api";

/** Live isolation state (egress blocked = ok) — gates active-playbook Run. */
export function useIsolationOk(): boolean {
  const [ok, setOk] = useState(false);
  useEffect(() => {
    let alive = true;
    const probe = () =>
      authFetch("/isolation/check")
        .then((r) => (r.ok ? r.json() : null))
        .then((j) => alive && setOk(!!j?.ok))
        .catch(() => alive && setOk(false));
    probe();
    const t = setInterval(probe, 15_000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);
  return ok;
}
