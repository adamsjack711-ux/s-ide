# s-ide docs

Design and reference notes for s-ide. Start with the [main README](../README.md) for the product overview and quick start; these documents go deeper on the security model and internals.

| Document | What it covers |
|---|---|
| [SANDBOX-DESIGN.md](SANDBOX-DESIGN.md) | The learning sandbox: data model, fix-in-place (Monaco → lab container), isolation self-check, WSTG/PTES methodology coverage. |
| [SAFETY-LAYER.md](SAFETY-LAYER.md) | Provenance (`lab` / `owned` / `external`), the authorization attestation gate, and how static findings are confidence-tagged against the dynamic evidence chain. |
| [TOOL-CHECKLIST.md](TOOL-CHECKLIST.md) | Per-tool porting checklist: tier legend, exposure model, and the arsenal inventory behind the capability gate. |
