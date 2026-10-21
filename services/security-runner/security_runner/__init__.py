"""Security runner service authenticated Docker-owning execution backend.

Merged from model-tools/runner/app.py. Owns Docker and creates ephemeral
containers for security tool execution. Lives on the black-onyx-runner
network (internal-only, never exposed to the browser).
"""
