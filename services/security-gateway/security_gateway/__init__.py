"""Security gateway receives BFF-proxied requests, dispatches to the runner.

Slimmed-down version of model-tools/gateway/app.py. Receives requests from
the Black Onyx BFF (routes_security.py), validates the bearer token, and
dispatches tool calls to the security-runner over HTTP.
"""
