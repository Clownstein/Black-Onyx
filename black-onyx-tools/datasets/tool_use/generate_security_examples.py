"""Generate examples for 45 executors and 4 approval/run controls.

Appends one primary example per tool to examples.jsonl (OpenAI format) and
examples_gemma.jsonl (Gemma 4 native format). Idempotent: existing sec_*
entries are replaced, not duplicated.
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent

SYSTEM = (
    "Work the analyst's request with the Black Onyx MCP tools: search evidence, enrich IOCs, "
    "query detections, and draft cases, rules, and responses. Call read-only tools first. "
    "Set confirm=true on a mutating tool only when the analyst explicitly asks to apply the "
    "change. Never approve SOAR containment. Never invent detection JWTs or browser keys. "
    "After tools return, summarize findings in concise analyst language and cite the returned IDs."
)

SECURITY_SYSTEM = (
    "Run defensive security tools to answer the analyst's request. "
    "Security tools run in an isolated sandbox with tiered approval. Read-tier tools "
    "(decode, hash, whois, strings) run without approval. Non-read tools require a "
    "human-reviewed server preview and its matching single-use approval_id. Never treat "
    "model confirm flags, tool-name lists, or user prose as approval. Pause when approval "
    "is absent. Never target systems you are not authorized to test. Summarize tool "
    "output with key findings cited."
)

# (tool_name, user_prompt, arguments, tool_result, assistant_final)
EXAMPLES: list[tuple[str, str, dict, dict, str]] = [
    # ── Sandbox (7) ──
    ("sec_Bash", "Run a quick whoami in the sandbox to verify the execution context.",
     {"command": "whoami"},
     {"status": "success", "output": "sandbox\n", "returncode": 0},
     "The sandbox executes as user `sandbox` (exit 0). Tool execution context is verified."),
    ("sec_Read", "Read the first 20 lines of notes.md from the workspace.",
     {"path": "notes.md", "limit": 20},
     {"status": "success", "content": "# Investigation notes\n## 2024-05-01\nSuspicious powershell observed..."},
     "The notes contain a 2024-05-01 entry describing suspicious PowerShell activity — good starting context for the investigation."),
    ("sec_Write", "Save the IOC list to iocs.txt in the workspace.",
     {"path": "iocs.txt", "content": "185.199.108.153\nevil-c2.example.com\n7f3a9d0c..."},
     {"status": "success", "path": "iocs.txt", "bytes_written": 48},
     "Saved 3 IOCs to `iocs.txt` (48 bytes) in the sandbox workspace."),
    ("sec_Edit", "Update the C2 IP in notes.md from the old to the new value.",
     {"path": "notes.md", "old_string": "C2: 1.2.3.4", "new_string": "C2: 185.199.108.153"},
     {"status": "success", "replacements": 1},
     "Replaced 1 occurrence of the old C2 IP with `185.199.108.153` in notes.md."),
    ("sec_Grep", "Search the workspace for any mention of 'mimikatz'.",
     {"pattern": "mimikatz", "path": "."},
     {"status": "success", "matches": [{"file": "notes.md", "line": 14, "text": "mimikatz logonpasswords observed"}]},
     "Found 1 match: `notes.md:14` mentions `mimikatz logonpasswords` — consistent with credential dumping."),
    ("sec_Glob", "List all PCAP files in the workspace.",
     {"pattern": "**/*.pcap", "path": "."},
     {"status": "success", "files": ["captures/session1.pcap", "captures/session2.pcap"]},
     "Found 2 PCAP files: `captures/session1.pcap` and `captures/session2.pkap`. I can analyze them with sec_analyze_pcap."),
    ("sec_ListFiles", "Show me what's in the workspace root.",
     {"path": "."},
     {"status": "success", "entries": [{"name": "notes.md", "type": "file"}, {"name": "captures", "type": "dir"}]},
     "Workspace contains `notes.md` and a `captures/` directory with packet data."),
    # ── Security (9) ──
    ("sec_nmap_scan", "Run a fast nmap scan against the registered lab host 10.88.0.2.",
     {"target": "10.88.0.2", "ports": "22,80,443"},
     {"status": "success", "output": "22/tcp open ssh\n80/tcp open http\n443/tcp open https"},
     "Lab host 10.88.0.2 exposes SSH (22), HTTP (80), and HTTPS (443). The HTTP service may be worth a follow-up nikto scan."),
    ("sec_sqlmap_scan", "Check the registered lab web app at http://10.88.0.2/search for SQL injection.",
     {"url": "http://10.88.0.2/search", "timeout": 60},
     {"status": "success", "output": "[WARNING] GET parameter 'q' is vulnerable: boolean-based blind"},
     "sqlmap found a boolean-based blind SQLi in the `q` parameter of `/search`. Recommend parameterized queries and input validation."),
    ("sec_nikto_scan", "Run nikto against the registered lab at http://10.88.0.2 to check for common misconfigurations.",
     {"target": "http://10.88.0.2"},
     {"status": "success", "output": "+ OSVDB-3268: /admin/: Admin directory found"},
     "nikto found an exposed `/admin/` directory (OSVDB-3268). Recommend access restrictions on that path."),
    ("sec_whois_lookup", "Who owns evil-c2.example.com?",
     {"domain": "evil-c2.example.com"},
     {"status": "success", "registrar": "Example Registrar", "created": "2024-04-01", "name_servers": ["ns1.example-dns.net"]},
     "`evil-c2.example.com` was registered 2024-04-01 via Example Registrar — recently created, consistent with campaign infrastructure."),
    ("sec_shodan_search", "What does Shodan know about 185.199.108.153?",
     {"query": "ip:185.199.108.153"},
     {"status": "success", "ip": "185.199.108.153", "ports": [443], "organization": "Example Hosting", "hostnames": [], "vulnerabilities": []},
     "Shodan reports 185.199.108.153 on TCP 443 under Example Hosting — infrastructure consistent with the C2 profile."),
    ("sec_gobuster_dir", "Check directories on the registered lab at http://10.88.0.2 with the bundled bounded wordlist.",
     {"url": "http://10.88.0.2"},
     {"status": "success", "found": ["/admin (200)", "/backup (200)", "/uploads (301)"]},
     "gobuster found `/admin` (200), `/backup` (200), and `/uploads` (301). The `/backup` directory is a high-priority review target."),
    ("sec_hydra_brute", "Test the registered lab SSH service on 10.88.0.2 with the bundled bounded credential fixture.",
     {"target": "10.88.0.2", "service": "ssh", "timeout": 30},
     {"status": "success", "output": "[22][ssh] host: 10.88.0.2 login: admin password: lab-admin"},
     "hydra found weak credentials `admin:lab-admin` on SSH — recommend immediate password rotation and fail2ban."),
    ("sec_tcpdump_capture", "Capture 15 seconds of traffic on eth0 filtered to port 443 — approved.",
     {"duration": 15, "filter": "port 443"},
     {"status": "success", "output": "142 packets captured\n98 packets received by filter"},
     "Captured 142 packets in 15s on port 443 — I can analyze the PCAP with tshark if needed."),
    ("sec_port_scan", "Quick TCP scan of ports 1 through 64 on the registered lab host 10.88.0.2.",
     {"target": "10.88.0.2", "ports": "1-64"},
     {"status": "success", "open": [22]},
     "Port 22 is open within the approved 1-64 range on 10.88.0.2 — consistent with the earlier nmap results."),
    # ── Binary RE (10) ──
    ("sec_checksec", "Check the security properties of suspicious_binary.exe.",
     {"path": "suspicious_binary.exe"},
     {"status": "success", "relro": "partial", "canary": "no", "nx": "yes", "pie": "no"},
     "The binary has partial RELRO, no stack canary, and no PIE — exploitable memory-corruption surface if a bug exists."),
    ("sec_decompile", "Decompile suspicious_binary.exe to understand its main logic.",
     {"path": "suspicious_binary.exe"},
     {"status": "success", "decompiled": "int main() { connect(\"185.199.108.153\", 4444); exec_shell(); }"},
     "The decompiled `main` connects to `185.199.108.153:4444` and spawns a shell — this is a reverse-shell implant."),
    ("sec_decompile_function", "Decompile the function 'beacon' in implant.bin.",
     {"path": "implant.bin", "function": "beacon"},
     {"status": "success", "decompiled": "void beacon() { sleep(60); http_get(\"http://c2/x\"); }"},
     "The `beacon` function sleeps 60s then beacons over HTTP to `/x` — classic C2 check-in behavior."),
    ("sec_disassemble", "Disassemble suspicious_binary.exe with objdump.",
     {"path": "suspicious_binary.exe"},
     {"status": "success", "instructions": 1284},
     "Disassembled 1284 instructions — the call graph shows network setup followed by exec, confirming implant behavior."),
    ("sec_disassemble_binary", "Disassemble implant.bin with radare2 for a richer view.",
     {"path": "implant.bin"},
     {"status": "success", "functions": ["main", "beacon", "encode_payload"]},
     "r2 identifies 3 functions: `main`, `beacon`, and `encode_payload` — the encoder suggests payload obfuscation."),
    ("sec_extract_strings", "Extract strings from suspicious_binary.exe — minimum length 6.",
     {"path": "suspicious_binary.exe", "min_length": 6},
     {"status": "success", "strings": ["185.199.108.153", "/tmp/.cache", "Mozilla/5.0"]},
     "Strings reveal the C2 `185.199.108.153`, a drop path `/tmp/.cache`, and a browser UA — implant indicators confirmed."),
    ("sec_run_binary", "Run sample.bin in the sandbox with a 10s timeout to observe behavior — approved.",
     {"path": "sample.bin", "timeout": 10},
     {"status": "success", "output": "connecting...\nfailed: no route", "returncode": 1},
     "The binary attempted a network connection and failed (no route — sandbox is offline). Confirms network-dependent behavior."),
    ("sec_file_info", "Get file type and headers for suspicious_binary.exe.",
     {"path": "suspicious_binary.exe"},
     {"status": "success", "file": "ELF 64-bit x86-64", "entry": "0x401000", "sections": 9},
     "The file is a 64-bit ELF with entry `0x401000` and 9 sections — a Linux implant despite the .exe name."),
    ("sec_search_gadgets", "Search for ROP gadgets in the implant binary.",
     {"path": "implant.bin"},
     {"status": "success", "gadgets": 47, "pop_rdi": 3},
     "Found 47 ROP gadgets including 3 `pop rdi` — enough for a ret2libc chain if a overflow exists."),
    ("sec_cyclic_pattern", "Generate a 200-byte cyclic pattern for crash offset detection.",
     {"size": 200},
     {"status": "success", "pattern": "aaaabaaacaaadaaaeaaaf..."},
     "Generated a 200-byte cyclic pattern — on crash, the value in RIP/EIP will reveal the exact overflow offset."),
    # ── Crypto/DFIR (11) ──
    ("sec_aes_encrypt", "Encrypt the string 'incident-notes' with key 'sixteen-byte-key!' for a evidence seal.",
     {"data": "incident-notes", "key": "sixteen-byte-key!"},
     {"status": "success", "ciphertext": "base64:aGVsbG8="},
     "Encrypted the evidence string with AES-GCM. Ciphertext (base64): `aGVsbG8=`."),
    ("sec_aes_decrypt", "Decrypt this base64 blob with key 'sixteen-byte-key!': aGVsbG8=",
     {"data": "aGVsbG8=", "key": "sixteen-byte-key!"},
     {"status": "success", "plaintext": "incident-notes"},
     "Decrypted blob reads `incident-notes` — matches the evidence label from the case."),
    ("sec_decode_hex", "Decode the hex string 48656c6c6f20576f726c64.",
     {"data": "48656c6c6f20576f726c64"},
     {"status": "success", "decoded": "Hello World"},
     "The hex decodes to `Hello World` — benign test string."),
    ("sec_decode_base64", "Decode aGVsbG8gd29ybGQ=",
     {"data": "aGVsbG8gd29ybGQ="},
     {"status": "success", "decoded": "hello world"},
     "The base64 decodes to `hello world` — benign test string."),
    ("sec_encode_base64", "Encode 'incident-2024-05-01-final' to base64 for transport.",
     {"data": "incident-2024-05-01-final"},
     {"status": "success", "encoded": "aW5jaWRlbnQtMjAyNC0wNS0wMS1maW5hbA=="},
     "Base64: `aW5jaWRlbnQtMjAyNC0wNS0wMS1maW5hbA==` — safe for header transport."),
    ("sec_hash_data", "Compute SHA-256 of the ransom note text.",
     {"data": "YOUR FILES HAVE BEEN ENCRYPTED", "algorithm": "sha256"},
     {"status": "success", "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
     "SHA-256: `e3b0c442...b7852b855` — record this hash in the case for dedup with known ransom notes."),
    ("sec_extract_iocs", "Extract IOCs from this email body: 'Contact us at evil@phish.example or visit http://185.199.108.153/login'.",
     {"text": "Contact us at evil@phish.example or visit http://185.199.108.153/login"},
     {"status": "success", "iocs": [{"type": "email", "value": "evil@phish.example"}, {"type": "url", "value": "http://185.199.108.153/login"}, {"type": "ip", "value": "185.199.108.153"}]},
     "Extracted 3 IOCs: email `evil@phish.example`, URL `http://185.199.108.153/login`, and IP `185.199.108.153`. I can enrich or add these to a case."),
    ("sec_compute_threat_score", "Compute a threat score for these 3 extracted IOCs.",
     {"iocs": json.dumps([{"type": "ip", "value": "185.199.108.153", "confidence": 40}, {"type": "url", "value": "http://185.199.108.153/login", "confidence": 25}, {"type": "email", "value": "evil@phish.example", "confidence": 13}])},
     {"status": "success", "score": 78, "severity": "high", "factors": ["known_c2_ip", "phishing_url_pattern"]},
     "Threat score is 78/100 (high) — driven by a known C2 IP and phishing URL pattern. Recommend immediate watchlist addition."),
    ("sec_add_ioc_to_case", "Add the IP 185.199.108.153 to case CASE-2024-0512.",
     {"case_id": "CASE-2024-0512", "ioc_type": "ip", "ioc_value": "185.199.108.153"},
     {"status": "success", "case_id": "CASE-2024-0512", "added": "185.199.108.153"},
     "Added IP `185.199.108.153` to CASE-2024-0512 as an IOC."),
    ("sec_generate_yara_rule", "Generate a YARA rule named RansomNote_Encryptor matching 'YOUR FILES HAVE BEEN ENCRYPTED'.",
     {"name": "RansomNote_Encryptor", "strings": "YOUR FILES HAVE BEEN ENCRYPTED", "condition": "all of them"},
     {"status": "success", "compiled": True, "rule": "rule RansomNote_Encryptor { strings: $a = \"YOUR FILES...\" condition: all of them }"},
     "YARA rule `RansomNote_Encryptor` compiled successfully — ready to deploy to the detection pipeline."),
    ("sec_analyze_pcap", "Analyze captures/session1.pcap for HTTP traffic.",
     {"path": "captures/session1.pcap", "filter": "http"},
     {"status": "success", "packets": 412, "http_requests": [{"host": "185.199.108.153", "uri": "/x"}]},
     "The PCAP shows 412 packets with repeated HTTP GETs to `185.199.108.153/x` — matches the implant beacon pattern."),
    # ── Web3 (8) ──
    ("sec_cast_call", "Call the balanceOf function on contract 0x1234... for address 0x5678... on our local RPC.",
     {"to": "0x0000000000000000000000000000000000001234", "data": "0x70a082310000000000000000000000000000000000000000000000000000000000005678", "rpc_url": "http://10.88.0.2:8545"},
     {"status": "success", "result": "0x0000...0064"},
     "balanceOf returned `0x64` (100 tokens) — the address holds 100 units of the contract token."),
    ("sec_cast_send", "Send a test transaction to the registered Anvil lab; an unlocked test account signs it after admin approval.",
     {"to": "0x0000000000000000000000000000000000000001", "sender": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "data": "0x", "value": "0", "rpc_url": "http://10.88.0.2:8545"},
     {"status": "success", "tx_hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
     "The registered Anvil node confirmed the approved transaction. No signing key entered the gateway or tool job."),
    ("sec_cast_keccak", "Compute the keccak256 hash of 'transfer(address,uint256)'.",
     {"data": "transfer(address,uint256)"},
     {"status": "success", "hash": "0xa9059cbb2ab09eb219583f4a59a5d0623ade346d962933d0f22f9f2e69f1a2d6"},
     "keccak256: `0xa9059cbb...` — this is the standard ERC-20 `transfer` selector prefix."),
    ("sec_compile_contracts", "Compile the contracts in the challenge directory with forge.",
     {"path": "challenge/"},
     {"status": "success", "compiled": 3, "warnings": 1},
     "Compiled 3 contracts with 1 warning (unused variable in Challenge.sol)."),
    ("sec_analyze_contract", "Run Slither on the challenge contract.",
     {"path": "challenge/Challenge.sol"},
     {"status": "success", "findings": [{"check": "reentrancy-eth", "impact": "High", "confidence": "Medium"}]},
     "Slither flagged a high-impact reentrancy (medium confidence) in the withdrawal path — classic reentrancy pattern to verify."),
    ("sec_get_contract_storage", "Read storage slots 0-2 of contract 0x1234 on the local RPC.",
     {"address": "0x0000000000000000000000000000000000001234", "slots": "0,1,2", "rpc_url": "http://10.88.0.2:8545"},
     {"status": "success", "storage": {"0": "0x...owner", "1": "0x...balance", "2": "0x...flag"}},
     "Slot 0 holds the owner, slot 1 the balance mapping root, and slot 2 a flag — the flag at slot 2 is the likely CTF target."),
    ("sec_check_solved", "Check whether the registered reference-basic challenge is solved.",
     {"challenge_id": "reference-basic"},
     {"status": "success", "output": json.dumps({"challenge_id": "reference-basic", "solved": False,
       "description": "Submit the reference flag as plain text; submissions are compared, never executed."}, sort_keys=True), "returncode": 0},
     "The registered reference challenge is not solved yet."),
    ("sec_submit_solution", "Submit the registered reference-basic answer — approved.",
     {"challenge_id": "reference-basic", "solution": "flag{black_onyx_reference}"},
     {"status": "success", "output": json.dumps({"challenge_id": "reference-basic", "accepted": True, "solved": True}, sort_keys=True), "returncode": 0},
     "The registered reference answer was accepted."),
]

CONTROL_EXAMPLES: list[tuple[str, str, dict, dict, str]] = [
    (
        "sec_preview_tool",
        "Prepare an exact preview for writing the reviewed IOC list to iocs.txt. Do not execute it.",
        {
            "tool_name": "Write",
            "arguments": {"path": "iocs.txt", "content": "185.199.108.153\n"},
        },
        {
            "tool": "Write",
            "tier": "write",
            "arguments": {"path": "iocs.txt", "content": "185.199.108.153\n"},
            "session_id": "mcp-security",
            "timeout": 60,
            "network_profile": "offline",
            "destinations": [],
            "ports": [],
            "lab_profile_id": None,
            "resolved_targets": {},
            "preview_hash": "d57f3f64d51b0ff08442b42fc3d7f240f8b56c43dfa346120c3260b99b20ae38",
        },
        "The server issued an exact write preview. It still needs explicit human review and approval before execution.",
    ),
    (
        "sec_approve_tool",
        "I reviewed this exact server preview, including its hash and IOC content. Approve it once.",
        {
            "tool_name": "Write",
            "preview": {
                "tool": "Write",
                "tier": "write",
                "arguments": {"path": "iocs.txt", "content": "185.199.108.153\n"},
                "session_id": "mcp-security",
                "timeout": 60,
                "network_profile": "offline",
                "destinations": [],
                "ports": [],
                "lab_profile_id": None,
                "resolved_targets": {},
                "preview_hash": "d57f3f64d51b0ff08442b42fc3d7f240f8b56c43dfa346120c3260b99b20ae38",
            },
        },
        {"approval_id": "approval_01JWRITEPREVIEW", "expires_at": "2026-09-30T16:05:00Z"},
        "The exact preview now has a short-lived, single-use approval ID. It is valid only for that unchanged request.",
    ),
    (
        "sec_agent_run_status",
        "Show the pending call for security agent run run_01JLAB before I decide.",
        {"run_id": "run_01JLAB"},
        {
            "run_id": "run_01JLAB",
            "status": "pending_approval",
            "pending_call": {
                "tool": "nmap_scan",
                "preview_hash": "f14c0d52dd5703932ae89646a0c671c60f7e1fc5d3fc1bbd79d0a9cab85092de",
                "arguments": {"target": "10.88.0.2", "ports": "80,443"},
            },
        },
        "Run `run_01JLAB` is paused. Its pending nmap call targets the registered lab host on TCP 80 and 443; no execution has occurred.",
    ),
    (
        "sec_agent_run_resume",
        "I reviewed and approved the pending preview. Resume run_01JLAB with approval_01JLABSCAN.",
        {"run_id": "run_01JLAB", "approval_id": "approval_01JLABSCAN"},
        {"run_id": "run_01JLAB", "status": "completed"},
        "The approved pending call completed and the run resumed. The approval cannot authorize another request.",
    ),
]

_LAB_HOST = "10.88.0.2"
NETWORK_EXAMPLE_SCOPE: dict[str, dict] = {
    "nmap_scan": {"network_profile": "lab", "destinations": [_LAB_HOST], "scope_ports": [22, 80, 443], "lab_profile_id": "reference-lab", "resolved_targets": {_LAB_HOST: [_LAB_HOST]}},
    "sqlmap_scan": {"network_profile": "lab", "destinations": [_LAB_HOST], "scope_ports": [80], "lab_profile_id": "reference-lab", "resolved_targets": {_LAB_HOST: [_LAB_HOST]}},
    "nikto_scan": {"network_profile": "lab", "destinations": [_LAB_HOST], "scope_ports": [80], "lab_profile_id": "reference-lab", "resolved_targets": {_LAB_HOST: [_LAB_HOST]}},
    "gobuster_dir": {"network_profile": "lab", "destinations": [_LAB_HOST], "scope_ports": [80], "lab_profile_id": "reference-lab", "resolved_targets": {_LAB_HOST: [_LAB_HOST]}},
    "hydra_brute": {"network_profile": "lab", "destinations": [_LAB_HOST], "scope_ports": [22], "lab_profile_id": "reference-lab", "resolved_targets": {_LAB_HOST: [_LAB_HOST]}},
    "port_scan": {"network_profile": "lab", "destinations": [_LAB_HOST], "scope_ports": list(range(1, 65)), "lab_profile_id": "reference-lab", "resolved_targets": {_LAB_HOST: [_LAB_HOST]}},
    "tcpdump_capture": {"network_profile": "lab", "lab_profile_id": "reference-lab", "resolved_targets": {}},
    "cast_call": {"network_profile": "lab", "destinations": [_LAB_HOST], "scope_ports": [8545], "lab_profile_id": "reference-lab", "resolved_targets": {_LAB_HOST: [_LAB_HOST]}},
    "cast_send": {"network_profile": "lab", "destinations": [_LAB_HOST], "scope_ports": [8545], "lab_profile_id": "reference-lab", "resolved_targets": {_LAB_HOST: [_LAB_HOST]}},
    "get_contract_storage": {"network_profile": "lab", "destinations": [_LAB_HOST], "scope_ports": [8545], "lab_profile_id": "reference-lab", "resolved_targets": {_LAB_HOST: [_LAB_HOST]}},
}


def _openai_tool_call_to_gemma(name: str, arguments: str | dict, *, call_id: str = "") -> str:
    if isinstance(arguments, str):
        try:
            args_obj = json.loads(arguments)
        except json.JSONDecodeError:
            args_obj = {"raw": arguments}
    else:
        args_obj = dict(arguments or {})
    parts: list[str] = []
    for key, value in args_obj.items():
        if isinstance(value, str):
            parts.append(f'{key}:<|"|>{value}<|"|>')
        elif isinstance(value, bool):
            parts.append(f"{key}:{str(value).lower()}")
        elif value is None:
            parts.append(f"{key}:null")
        elif isinstance(value, list):
            inner = ",".join(json.dumps(v) if not isinstance(v, str) else f'<|"|>{v}<|"|>' for v in value)
            parts.append(f"{key}:[{inner}]")
        else:
            parts.append(f"{key}:{value}")
    cid = call_id or f"call_{name}"
    return f"<|tool_call>call:{name}:{cid}{{{','.join(parts)}}}<tool_call|>"


def build_tool_def(sec_name: str, description: str, schema: dict) -> dict:
    return {"type": "function", "function": {"name": sec_name, "description": description, "parameters": schema}}


def main() -> None:
    from black_onyx_tools.tools.sec_tools import (
        SECURITY_CONTROL_CATALOG,
        SECURITY_READ_ONLY_TOOLS,
        SECURITY_TOOL_CATALOG,
        public_security_tool_schema,
    )

    catalog = {**SECURITY_TOOL_CATALOG, **SECURITY_CONTROL_CATALOG}

    openai_lines: list[str] = []
    gemma_lines: list[str] = []
    seen: set[str] = set()
    count = 0

    for sec_name, user, arguments, tool_result, final in EXAMPLES + CONTROL_EXAMPLES:
        base_name = sec_name.removeprefix("sec_")
        assert base_name in catalog, f"Unknown tool in EXAMPLES: {base_name}"
        description, schema = catalog[base_name]
        seen.add(sec_name)

        effective_user = user
        effective_arguments = dict(arguments)
        if base_name in SECURITY_TOOL_CATALOG:
            schema = public_security_tool_schema(base_name)
            effective_arguments.update(NETWORK_EXAMPLE_SCOPE.get(base_name, {}))
            if base_name not in SECURITY_READ_ONLY_TOOLS:
                approval_id = f"approval_reviewed_{base_name.lower()}"
                effective_arguments["approval_id"] = approval_id
                effective_user = (
                    f"{user}\n\nThe prior human-reviewed server preview returned "
                    f"single-use approval ID {approval_id}; use it only for this exact request."
                )

        example_id = f"sec_{base_name}_01"
        call_id = f"call_{example_id}"
        tool_def = build_tool_def(sec_name, description, schema)
        args_json = json.dumps(effective_arguments)

        openai_entry = {
            "id": example_id,
            "tool": sec_name,
            "tags": [sec_name],
            "messages": [
                {"role": "system", "content": SECURITY_SYSTEM},
                {"role": "user", "content": effective_user},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {"id": call_id, "type": "function", "function": {"name": sec_name, "arguments": args_json}}
                    ],
                },
                {"role": "tool", "tool_call_id": call_id, "name": sec_name, "content": json.dumps(tool_result)},
                {"role": "assistant", "content": final},
            ],
            "tools": [tool_def],
        }
        openai_lines.append(json.dumps(openai_entry, ensure_ascii=False))

        gemma_call = _openai_tool_call_to_gemma(sec_name, effective_arguments, call_id=call_id)
        tool_response = f"<|tool_response>response:{sec_name}{{status:<|\"|>success<|\"|>,output:<|\"|>{json.dumps(tool_result)}<|\"|>}}<tool_response|>"
        gemma_entry = {
            "id": f"gemma_{example_id}",
            "format": "gemma4_native",
            "tool": sec_name,
            "tags": ["gemma4", sec_name],
            "messages": [
                {"role": "system", "content": SECURITY_SYSTEM},
                {"role": "user", "content": effective_user},
                {"role": "assistant", "content": gemma_call},
                {"role": "user", "content": f"Tool result (untrusted evidence):\n{tool_response}\n\nContinue. Prefer a final JSON answer when ready."},
                {"role": "assistant", "content": json.dumps({"final": True, "answer": final})},
            ],
            "tools": [tool_def],
        }
        gemma_lines.append(json.dumps(gemma_entry, ensure_ascii=False))
        count += 1

    # Verify full coverage of all security executors and lifecycle controls.
    all_sec = {f"sec_{name}" for name in catalog}
    missing = all_sec - seen
    if missing:
        raise SystemExit(f"Missing examples for: {sorted(missing)}")
    assert count == 49, f"Expected 49 examples, generated {count}"

    # Replace existing sec_* lines (idempotent) and append new ones
    for path, lines in ((OUT / "examples.jsonl", openai_lines), (OUT / "examples_gemma.jsonl", gemma_lines)):
        existing = [
            line for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and '"tool": "sec_' not in line
        ]
        merged = existing + lines
        path.write_text("\n".join(merged) + "\n", encoding="utf-8")
        print(f"{path.name}: {len(existing)} existing + {len(lines)} security = {len(merged)} total")

    print(f"Generated {count} security tool examples (OpenAI + Gemma formats)")


if __name__ == "__main__":
    main()
