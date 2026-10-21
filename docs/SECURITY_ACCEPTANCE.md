# Security and full-stack acceptance gates

The source checks do not enable networked executors. `SECURITY_EGRESS_VERIFIED` and `SECURITY_CAPTURE_VERIFIED` must remain `false` until the independent checks below pass on the published images and the deployed runtime. Record image digests, kernel/CNI versions, observer logs, and cleanup results with the release evidence.

## Images

Build the toolbox and guard from the reviewed digest-pinned bases and frozen package snapshot. Run `scripts/scan-security-images.ps1` with the four published repository digests (toolbox, guard, runner, gateway). The script refuses tags and local images without matching repository digests, runs Trivy vulnerability/secret/misconfiguration scans, then tests toolbox imports, required binaries, bounded wordlists, guard tools, and service imports. A Docker daemon, local final images, approved scan packages, and Trivy are required.

## Kubernetes NetworkPolicy enforcement

Run the source/denial pair on the production CNI, using a digest-pinned probe image that contains Python 3:

```powershell
./scripts/test-networkpolicy-enforcement.ps1 `
  -DestinationNamespace black-onyx-app `
  -ProbeImage 'registry.example/black-onyx-probe@sha256:REPLACE_WITH_PUBLISHED_DIGEST' `
  -DestinationApp incident-api `
  -AllowedSourceNamespace black-onyx-app `
  -AllowedSourceApp black-onyx `
  -DestinationPort 8083
```

The test starts a target selected by the real destination label, proves the matching in-namespace source reaches it, then tries the same source label from a different namespace and requires denial. Repeat for the actual selectors and ports in `networkpolicy-allow-edge.yaml` (for example, correlation to notification-service and asset-registry, BFF to integration-hub, and processing to incident-api). A failed allowed connection is inconclusive; a successful cross-namespace connection means the policy gate failed.

## Per-job executor firewall

Use a separate observer and known-live positive controls outside the executor trust domain. For each test below, first prove the observation endpoint is reachable from an approved control workload, then run the attempt through the real security gateway, runner, digest-pinned toolbox, and guard. Capture packets at the Docker host/network boundary and application observer; do not use the runner's own result as the only evidence.

| Attempt from an untrusted job | Required evidence |
| --- | --- |
| Approved hostname and TCP port | Only the preview-pinned IPv4 address and approved port reaches the observer. |
| DNS to a controlled resolver over UDP and TCP | No query reaches the resolver; hostname resolution uses the exact preview mapping. |
| Direct IP to an unapproved live observer and TCP port | The control workload reaches it; the job produces no packet at the observer. |
| HTTP redirect from an approved server to a different observer | The redirect response is received; no follow-up packet reaches the second observer. |
| IPv6 literal, UDP probe, and raw-frame attempt | No IPv6/UDP frame reaches the observer; the toolbox has no raw-socket capability. |
| Metadata address, Docker/Kubernetes API ports, host gateway, and an unregistered lab address | No request reaches any service or control-plane observer. |
| Concurrent jobs with different target/port approvals | Each job reaches only its own exact destinations and ports. |
| `cast_send` with valid and invalid RPC fixtures | Only the registered private Anvil IP:8545 receives calls; non-Anvil nodes, chain IDs other than 31337, locked senders, changed request fields, and receipt failures are rejected; no key or mnemonic reaches the job. |
| Firewall install failure, job cancellation, runner restart, and timeout | No toolbox starts without the filter; containers, guard namespaces, and policy files are removed. |

Run the matrix against public and registered internal lab networks. Keep both egress flags false if any row is inconclusive. `SECURITY_CAPTURE_VERIFIED` additionally requires proof that capture sees only the registered lab network, returns bounded PCAP bytes, and cleans up on cancel, timeout, and runner restart.

## Live Black Onyx acceptance

Source and contract suites still need to be run on a provisioned Python environment. Live release acceptance also requires an authenticated connector event to become a retained finding and incident with tenant-authorized evidence in the UI; verified identity and asset sightings to affect profile evaluation and risk; configured email/webhook outcomes; reviewed-data training to produce a signed model package; replica confirmation before promotion; and generation-fenced rollback confirmed by replicas. Exercise training beyond the UI's former 30-second window and resume it after a page remount.

Shodan, the TIP case IOC callback, registered challenge providers, CAPE/DRAKVUF, GPUs, and external model providers require their operator-managed credentials, owned labs, and live services. Run these against owned fixtures. Never treat config rendering, an image build, an import smoke, or mocked tests as live integration evidence.
