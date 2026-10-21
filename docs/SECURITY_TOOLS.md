# Security tool catalog

This reference is maintained against `services/security-gateway/security_gateway/tool_catalog.py`
and `execution_spec.py`. Every executor builds a structured `argv`; only `Bash`
uses a shell and it is gated by `ENABLE_BASH_TOOL`.

Status meanings:

- **enabled (baseline image):** runs with the POSIX/Python tools in the validated sandbox image.
- **needs image attestation:** the executor exists, but the gateway enables the tool once the runner's `/capabilities` probe attests the listed binaries/modules in the digest-pinned sandbox image.
- **needs enforced egress:** the executor exists, but network execution is disabled until a per-job packet filter and container-level escape tests are supplied. A Docker network name alone cannot enable it.
- **registered adapter:** a bounded server-side adapter exists; the gateway reports enabled only when its provider, persistence, or actor-bound app callback is ready.
- **needs capture attestation:** capture uses the trusted helper, but remains unavailable until a registered isolated lab and separate capture verification are present.
- **unsupported (503):** no trusted executor exists; requests fail instead of running a stand-in.

Workspace mount: `ro` tools cannot modify the session workspace.

| Tool | Category | Tier | Status | Gate | Requires | Mount | Behavior |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `Bash` | sandbox | destructive | enabled (baseline image) | ENABLE_BASH_TOOL | python3/coreutils | rw | Execute a bash command in the sandbox. |
| `Read` | sandbox | read | enabled (baseline image) |   | python3/coreutils | ro | Read file contents from the sandbox workspace. |
| `Write` | sandbox | workspace-write | enabled (baseline image) |   | python3/coreutils | rw | Write content to a file in the sandbox workspace. |
| `Edit` | sandbox | workspace-write | enabled (baseline image) |   | python3/coreutils | rw | Edit a file by replacing old_string with new_string. |
| `Grep` | sandbox | read | enabled (baseline image) |   | python3/coreutils | ro | Search for a regex pattern in files within the sandbox. |
| `Glob` | sandbox | read | enabled (baseline image) |   | python3/coreutils | ro | Find workspace files matching a glob pattern (supports recursive **). |
| `ListFiles` | sandbox | read | enabled (baseline image) |   | python3/coreutils | ro | List files in a directory. |
| `nmap_scan` | security | network | needs enforced egress |   | nmap | rw | Run nmap against a target. |
| `sqlmap_scan` | security | lab | needs enforced egress | SQLMAP_EXPLOIT_MODE | sqlmap | rw | Run sqlmap against a target URL. |
| `nikto_scan` | security | network | needs enforced egress |   | nikto | rw | Run nikto against a target. |
| `whois_lookup` | security | read | needs enforced egress |   | whois | rw | WHOIS lookup for a domain. |
| `shodan_search` | security | read | registered adapter | SHODAN_API_KEY | gateway | n/a | Bounded exact-IP/hostname lookup through the server-side Shodan adapter. |
| `gobuster_dir` | security | network | needs enforced egress |   | gobuster | rw | Directory brute-force with gobuster. |
| `hydra_brute` | security | destructive | needs enforced egress | ENABLE_HYDRA | hydra | rw | Brute-force with hydra. |
| `tcpdump_capture` | security | privileged-capture | needs capture attestation | ENABLE_TCPDUMP | digest-pinned guard + registered lab | n/a | Bounded capture inside an isolated registered lab namespace; returns a downloadable PCAP. |
| `port_scan` | security | network | needs enforced egress |   | nmap | rw | Quick TCP port scan. |
| `checksec` | binary | read | needs image attestation |   | checksec | ro | Check binary security properties. |
| `decompile` | binary | lab | needs image attestation |   | r2 | ro | Decompile to radare2 pseudo-C (pdc): one function if given, otherwise every analyzed function. |
| `decompile_function` | binary | lab | needs image attestation |   | r2 | ro | Decompile one function to radare2 pseudo-C (pdc). |
| `disassemble` | binary | lab | needs image attestation |   | objdump | ro | Disassemble a binary with objdump. |
| `disassemble_binary` | binary | lab | needs image attestation |   | r2 | ro | Disassemble with r2. |
| `extract_strings` | binary | read | needs image attestation |   | strings | ro | Extract strings from a binary. |
| `run_binary` | binary | destructive | needs image attestation |   | timeout | rw | Run a binary with timeout. |
| `file_info` | binary | read | needs image attestation |   | file | ro | Get file info (file, readelf). |
| `search_gadgets` | binary | lab | needs image attestation |   | ropper | ro | Search a binary for ROP gadgets matching an expression (ropper --search). |
| `cyclic_pattern` | binary | lab | needs image attestation |   | python3, pwn | ro | Generate cyclic pattern for offset finding. |
| `aes_encrypt` | crypto | read | needs image attestation |   | python3, cryptography | ro | AES-GCM encrypt data with a key. |
| `aes_decrypt` | crypto | read | needs image attestation |   | python3, cryptography | ro | AES-GCM decrypt data with a key. |
| `decode_hex` | crypto | read | enabled (baseline image) |   | python3/coreutils | ro | Decode hex to ASCII. |
| `decode_base64` | crypto | read | enabled (baseline image) |   | python3/coreutils | ro | Decode base64. |
| `encode_base64` | crypto | read | enabled (baseline image) |   | python3/coreutils | ro | Encode to base64. |
| `hash_data` | crypto | read | enabled (baseline image) |   | python3/coreutils | ro | Hash data (md5/sha1/sha256/sha512). |
| `extract_iocs` | crypto | read | enabled (baseline image) |   | python3/coreutils | ro | Extract IOCs from text. |
| `compute_threat_score` | crypto | read | enabled (baseline image) |   | python3/coreutils | ro | Compute composite threat score from IOC data. |
| `add_ioc_to_case` | crypto | workspace-write | registered adapter | SECURITY_GATEWAY_KEY + internal TIP BFF | gateway | n/a | Add an IOC through the actor-assertion-bound internal TIP endpoint. |
| `generate_yara_rule` | crypto | lab | needs image attestation |   | yara Python module | ro | Generate YARA source and compile-check its syntax. |
| `analyze_pcap` | crypto | lab | needs image attestation |   | tshark | ro | Analyze a PCAP with tshark. |
| `cast_call` | web3 | read | needs enforced egress |   | cast | rw | Read-only Ethereum contract call. |
| `cast_send` | web3 | transaction | registered private Anvil lab only | ENABLE_CAST_SEND | trusted bounded JSON-RPC helper | rw | Admin-approved transaction to Anvil chain ID 31337; Anvil's unlocked test account signs inside the owned node, with no key in the gateway or job. |
| `cast_keccak` | web3 | read | needs image attestation |   | cast | ro | Compute keccak256 hash. |
| `compile_contracts` | web3 | lab | needs image attestation |   | forge | rw | Compile Solidity contracts with forge. |
| `analyze_contract` | web3 | lab | needs image attestation |   | slither | rw | Analyze a contract with Slither. |
| `get_contract_storage` | web3 | read | needs enforced egress |   | cast | rw | Read contract storage slots. |
| `check_solved` | web3 | read | registered adapter |   | gateway | rw | Check the bundled reference challenge or an operator-registered challenge ID. |
| `submit_solution` | web3 | destructive | registered adapter | single-use admin approval | gateway | rw | Submit bounded text/JSON as data; the adapter never executes it. |

## Egress allowlist

Offline jobs use `network_mode=none`. Network jobs use a separate trusted
per-job firewall namespace: the runner resolves the previewed host once, signs
the exact IPv4 answers and TCP ports into the approval, installs a default-deny
nftables policy, then attaches the untrusted toolbox to that namespace. The
runner verifies the guard image digest and network labels; a bridge name alone
does not enable network tools. Keep `SECURITY_EGRESS_VERIFIED=false` until
independent observers complete direct-IP, DNS-change, redirect, private,
metadata, IPv6, UDP, host-gateway, concurrency, guard-failure, cancellation,
restart, and cleanup escape tests.
