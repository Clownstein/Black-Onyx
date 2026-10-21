# Semgrep rules for code-processor

Repository Semgrep YAML rule packs live in `rules/`. The `code-processor` production image installs Semgrep and copies these rules; configured scanner readiness fails when Semgrep or its rule pack is unavailable.

## How invocation works

1. On each code-change scan, `run_configured_semgrep()` validates and invokes `semgrep`.
2. If present, it runs:

   ```bash
   semgrep --config "$SEMGREP_CONFIG" --json --quiet <target>
   ```

   The production image sets `SEMGREP_CONFIG` to its copied repository rules. For a source checkout, set it explicitly:

   ```bash
   export SEMGREP_CONFIG=scanners/semgrep/rules
   ```

3. Parsed results are attached to the `code.change` event as `scanner_findings`.
4. Semgrep failure is reported as scanner failure. The separate regex heuristic capability runs only when explicitly enabled; it is never labeled as Semgrep output.

## Adding rules

Drop `.yml` / `.yaml` files under `rules/` and point `SEMGREP_CONFIG` at this directory (or a specific rule file).
