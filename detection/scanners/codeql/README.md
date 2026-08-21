# CodeQL

`services/code-processor/code_processor/codeql_runner.py` invokes the pinned CodeQL bundle,
creates bounded temporary databases for supported source languages, runs the official
security-and-quality suites, and normalizes SARIF results into `scanner_findings`.

CodeQL is disabled by default because it is substantially heavier than Semgrep. Enable it
with `CODE_PROCESSOR_CODEQL_ENABLED=true`. When enabled, a missing CLI or failed scan is
reported as `failed`; it is never replaced with heuristic findings.
