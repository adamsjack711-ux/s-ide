/**
 * Scandiff's secret-redaction entry point. The implementation is the shell-wide
 * lib/redact (one source of truth for the "never render a secret" invariant);
 * this re-export keeps the local import path stable for the panel/logic here.
 */
export { redactSecrets } from "../../lib/redact";
