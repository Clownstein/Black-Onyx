# LLM-assisted investigation

The Incident detail view can draft investigation notes using the configured
chat provider. When chat is unavailable, it creates a local template from the
incident title, severity, assets, findings, and evidence fields. Drafts remain
editable analyst content; Black Onyx does not post or execute them
automatically.

## Policy

- Suggestions may include hypotheses and ATT&CK techniques, which must be
  treated as possibilities rather than verified facts.
- Suggestions may identify questions for an analyst or propose follow-up
  queries.
- The assistant does not acknowledge, resolve, contain, or open cases; execute
  playbooks; or launch Velociraptor collections.
- Air-gap policy prevents incident data from being sent to public cloud LLM
  APIs.
- Analysts review and edit generated content before posting comments or
  dispositions.

## Configuration

1. Configure an approved local chat provider, such as Ollama, on a SOC
   workstation or internal GPU host.
2. Select the provider and model in Black Onyx settings.
3. Open the Investigation Assist panel from an incident. The panel presents
   generated content in an editable draft field.

If the configured chat provider is unavailable, the local template remains
available. Neither path writes to `incident-api` until an analyst submits a
separate action through the application.

## Operating boundary

The assistant is a user-initiated investigation aid. It does not participate in
automated correlation, response approval, or the Kafka inference path. These
boundaries preserve deterministic detection and human authorization for
response actions.
