"""Structured sandbox commands. User values are never parsed by a shell."""
from __future__ import annotations

import ipaddress
import re
import shlex
import socket
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from security_gateway.shodan_adapter import parse_query


class UnsupportedTool(ValueError):
    pass


UNSUPPORTED_TOOLS: frozenset[str] = frozenset()
NETWORK_TOOLS = frozenset({
    "nmap_scan", "sqlmap_scan", "nikto_scan", "whois_lookup",
    "gobuster_dir", "hydra_brute", "port_scan", "cast_call",
    "get_contract_storage", "cast_send",
})
# Live scanners the security agent may call. Hydra, packet capture, and
# Web3 transaction tools stay out of autonomous runs.
AGENT_NETWORK_TOOLS = frozenset({
    "nmap_scan", "nikto_scan", "whois_lookup", "gobuster_dir", "port_scan",
})
_RUN_BINARY_SCANNER_TOOLS = {
    "nikto": ("nikto_scan", "target"),
    "nmap": ("nmap_scan", "target"),
    "gobuster": ("gobuster_dir", "url"),
    "whois": ("whois_lookup", "domain"),
}
_RUN_BINARY_SHELLS = frozenset({"bash", "sh", "dash", "zsh", "csh", "ksh"})
_SIMPLE_COMMAND = re.compile(r"^[A-Za-z0-9._+-]+$")

# The runner's digest-pinned sandbox is operator supplied. Only these tools
# rely on POSIX/Python commands present in the validated baseline image.
# Other local analyzers require binary/dependency attestation before enabling.
BASELINE_TOOLS = frozenset({
    "Bash", "Read", "Write", "Edit", "Grep", "Glob", "ListFiles",
    "decode_hex", "encode_base64", "decode_base64", "hash_data",
    "extract_iocs", "compute_threat_score",
})

# Executables, Python modules, and image-owned helper files each non-baseline
# executor needs in the sandbox image. The runner's /capabilities probe attests them.
REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "checksec": ("bin:checksec",),
    "decompile": ("bin:r2",),
    "decompile_function": ("bin:r2",),
    "disassemble": ("bin:objdump",),
    "disassemble_binary": ("bin:r2",),
    "extract_strings": ("bin:strings",),
    "run_binary": ("bin:timeout",),
    "file_info": ("bin:file",),
    "search_gadgets": ("bin:ropper",),
    "cyclic_pattern": ("bin:python3", "py:pwn"),
    "aes_encrypt": ("bin:python3", "py:cryptography"),
    "aes_decrypt": ("bin:python3", "py:cryptography"),
    "analyze_pcap": ("bin:tshark",),
    "cast_keccak": ("bin:cast",),
    "compile_contracts": ("bin:forge", "bin:solc"),
    "analyze_contract": ("bin:slither",),
    "generate_yara_rule": ("py:yara",),
    "nmap_scan": ("bin:nmap",),
    "port_scan": ("bin:nmap",),
    "sqlmap_scan": ("bin:sqlmap",),
    "nikto_scan": ("bin:nikto",),
    "whois_lookup": ("bin:whois",),
    "gobuster_dir": ("bin:gobuster",),
    "hydra_brute": ("bin:hydra",),
    "cast_call": ("bin:cast",),
    "cast_send": ("helper:anvil_send.py",),
    "get_contract_storage": ("bin:cast",),
}

# Executors that never modify the workspace; the runner mounts it read-only.
READ_ONLY_TOOLS = frozenset({
    "Read", "Grep", "Glob", "ListFiles", "checksec", "decompile",
    "decompile_function", "disassemble", "disassemble_binary",
    "extract_strings", "file_info", "search_gadgets", "analyze_pcap",
    "cast_keccak", "aes_encrypt", "aes_decrypt", "decode_hex",
    "encode_base64", "decode_base64", "hash_data", "extract_iocs",
    "compute_threat_score", "cyclic_pattern",
    "generate_yara_rule",
})

MAX_GLOB_RESULTS = 500

HYDRA_SERVICE_PORTS = {
    "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "http-get": 80,
    "pop3": 110, "imap": 143, "https-get": 443, "smb": 445, "rdp": 3389,
    "mysql": 3306, "postgres": 5432, "mssql": 1433, "vnc": 5900,
}


# Preview/approval sentinel: [0] means all TCP to the pinned destination(s).
ALL_TCP_SCOPE = [0]


def is_all_tcp_scope(ports: list[int] | tuple[int, ...] | None) -> bool:
    return list(ports or []) == ALL_TCP_SCOPE


def parse_port_expression(expression: str) -> list[int]:
    """Parse a bounded comma/range expression into unique TCP ports."""
    if not isinstance(expression, str) or not expression or len(expression) > 256:
        raise ValueError("A TCP port scope is required")
    if expression.strip().lower() == "all":
        return list(ALL_TCP_SCOPE)
    ports: set[int] = set()
    for part in expression.split(","):
        part = part.strip()
        match = re.fullmatch(r"([0-9]{1,5})(?:-([0-9]{1,5}))?", part)
        if not match:
            raise ValueError("Ports must be comma-separated numbers or ranges")
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if not 1 <= start <= end <= 65535 or end - start > 63:
            raise ValueError("Each port range is limited to 64 consecutive ports")
        ports.update(range(start, end + 1))
        if len(ports) > 64:
            raise ValueError("At most 64 TCP ports may be approved")
    return sorted(ports)


def _host_port_from_url(value: str) -> tuple[str, int]:
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError("Target URL is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("Target must be an HTTP(S) URL without credentials or a fragment")
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise ValueError("Target URL port is invalid") from exc
    return parsed.hostname.lower(), port


def _validate_single_host(host: Any) -> str:
    if not isinstance(host, str) or not host or len(host) > 253:
        raise ValueError("A single target host is required")
    if any(character in host for character in "/\\,@; \t\r\n"):
        raise ValueError("Target must be one hostname or IPv4 address")
    if host.startswith("-") or "/" in host:
        raise ValueError("Target cannot be interpreted as a command option or range")
    if not re.fullmatch(r"(?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+|(?:[0-9]{1,3}\.){3}[0-9]{1,3}", host):
        raise ValueError("Target must be one hostname or IPv4 address")
    return host.lower()


def rewrite_agent_scanner_call(name: str, arguments: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Map ``run_binary`` scanner and shell wrappers onto the dedicated tools."""
    args = dict(arguments or {})
    if name != "run_binary":
        return name, args
    raw_path = str(args.get("path") or "")
    binary = PurePosixPath(raw_path).name.lower()
    timeout = args.get("timeout")
    timeout_arg = {"timeout": timeout} if isinstance(timeout, int) and not isinstance(timeout, bool) else {}
    mapped = _RUN_BINARY_SCANNER_TOOLS.get(binary)
    if mapped is not None:
        tool, field = mapped
        raw = str(args.get("args") or args.get(field) or "").strip()
        return tool, {field: raw, **timeout_arg}
    command = str(args.get("args") or args.get("command") or "").strip()
    if binary in _RUN_BINARY_SHELLS:
        if _SIMPLE_COMMAND.fullmatch(command) and command.lower() not in _RUN_BINARY_SCANNER_TOOLS:
            return "run_binary", {"path": command, **timeout_arg}
        return "Bash", {"command": command, **timeout_arg}
    if PurePosixPath(raw_path).is_absolute() and _SIMPLE_COMMAND.fullmatch(binary):
        rewritten = dict(args)
        rewritten["path"] = binary
        return "run_binary", rewritten
    return name, args


def network_profile_for_hosts(hosts: list[str]) -> str:
    """Public hostnames stay public; RFC1918/loopback literals need a lab profile."""
    for host in hosts:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            continue
        if address.is_private or address.is_loopback or address.is_link_local:
            return "lab"
    return "public"


def pin_public_targets(destinations: list[str]) -> dict[str, list[str]]:
    """Resolve public destinations on the gateway; the runner network has no public DNS."""
    if not destinations:
        raise ValueError("A bounded, non-empty destination list is required")
    pinned: dict[str, list[str]] = {}
    for raw in destinations:
        if not isinstance(raw, str) or not raw or len(raw) > 253:
            raise ValueError("Destinations must be IPv4 addresses or hostnames")
        host = raw.strip().lower()
        try:
            literal = ipaddress.ip_address(host)
            addresses = [literal]
        except ValueError:
            try:
                answers = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            except socket.gaierror as exc:
                raise ValueError(f"Cannot resolve destination: {host}") from exc
            addresses = sorted({ipaddress.ip_address(item[4][0]) for item in answers})
        if not addresses:
            raise ValueError(f"Destination has no IPv4 address: {host}")
        values: list[str] = []
        for address in addresses:
            if address.version != 4:
                raise ValueError("IPv6 is denied for sandbox jobs")
            if (
                address.is_loopback or address.is_link_local or address.is_multicast
                or address.is_unspecified or address.is_reserved or not address.is_global
            ):
                raise ValueError("Public jobs may reach only globally routed IPv4 addresses")
            values.append(str(address))
        pinned[host] = sorted(set(values))
    return pinned


def derive_network_scope(name: str, arguments: dict[str, Any]) -> tuple[list[str], list[int]]:
    """Derive the only host and TCP ports a structured network executor may use."""
    if name not in NETWORK_TOOLS:
        return [], []
    if name in {"nmap_scan", "port_scan"}:
        host = arguments.get("target")
        ports = parse_port_expression(arguments.get("ports", ""))
    elif name in {"sqlmap_scan", "gobuster_dir"}:
        host, port = _host_port_from_url(arguments.get("url", ""))
        ports = [port]
    elif name == "nikto_scan":
        raw_target = arguments.get("target", "")
        if "://" in raw_target:
            host, port = _host_port_from_url(raw_target)
        else:
            host, port = raw_target, 80
        ports = [port]
    elif name == "whois_lookup":
        host, ports = "whois.iana.org", [43]
    elif name == "hydra_brute":
        host = arguments.get("target")
        service = arguments.get("service")
        if service not in HYDRA_SERVICE_PORTS:
            raise ValueError("Hydra service is not in the approved service list")
        ports = [HYDRA_SERVICE_PORTS[service]]
    elif name == "cast_send":
        rpc_url = arguments.get("rpc_url", "")
        if not isinstance(rpc_url, str) or len(rpc_url) > 256:
            raise ValueError("An owned Anvil RPC URL is required")
        parsed = urlsplit(rpc_url)
        if (
            parsed.scheme.lower() != "http"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Transaction signing requires a plain HTTP owned Anvil RPC endpoint")
        try:
            address = ipaddress.ip_address(parsed.hostname)
            port = parsed.port or 8545
        except ValueError as exc:
            raise ValueError("Anvil RPC must use a literal private IPv4 address") from exc
        if (
            address.version != 4 or not address.is_private or address.is_loopback
            or address.is_link_local or address.is_multicast or address.is_unspecified
            or address.is_reserved or port != 8545
        ):
            raise ValueError("Anvil RPC must use a registered private IPv4 address on TCP 8545")
        host, ports = str(address), [port]
    elif name in {"cast_call", "get_contract_storage"}:
        host, port = _host_port_from_url(arguments.get("rpc_url", ""))
        ports = [port]
    else:
        raise UnsupportedTool(f"{name} has no network-scope validator")
    return [_validate_single_host(host)], ports


def build_execution(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    from security_gateway.tool_catalog import TOOL_CATALOG

    spec = TOOL_CATALOG.get(name)
    if spec is None:
        raise UnsupportedTool("Unknown tool")
    fields = spec["parameters"].get("properties", {})
    values = {key: field["default"] for key, field in fields.items() if "default" in field}
    values.update(arguments)
    if "path" in fields:
        path = values.get("path", ".")
        if (
            not isinstance(path, str) or not path or path.startswith("-")
            or "\\" in path or "\x00" in path
            or PurePosixPath(path).is_absolute()
            or ".." in PurePosixPath(path).parts
        ):
            raise ValueError("File path must remain relative to the session workspace")
    value = lambda key: str(values.get(key, ""))
    stdin = ""

    if name == "Bash":
        argv = ["/bin/sh", "-c", value("command")]
    elif name == "Read":
        offset, limit = int(values.get("offset", 1)), int(values.get("limit", 100))
        if offset < 1 or limit < 1 or limit > 10000:
            raise ValueError("Invalid read range")
        argv = ["sed", "-n", f"{offset},{offset + limit - 1}p", "--", value("path")]
    elif name == "ListFiles":
        argv = ["ls", "-la", "--", value("path")]
    elif name == "Grep":
        argv = ["grep", "-rn"]
        if value("glob"):
            argv.append(f"--include={value('glob')}")
        argv += ["--", value("pattern"), value("path")]
    elif name == "Glob":
        from security_gateway.glob_helper import SOURCE

        pattern = value("pattern")
        if (
            not pattern or pattern.startswith("/") or "\\" in pattern
            or "\x00" in pattern or ".." in PurePosixPath(pattern).parts
        ):
            raise ValueError("Glob pattern must stay inside the session workspace")
        # pathlib glob gives real recursive ``**`` semantics, unlike find -name.
        argv = ["python3", "-c", SOURCE, value("path"), pattern, str(MAX_GLOB_RESULTS)]
    elif name == "Write":
        argv = ["python3", "-c", "import pathlib,sys;pathlib.Path(sys.argv[1]).write_bytes(sys.stdin.buffer.read())", value("path")]
        stdin = value("content")
    elif name == "Edit":
        argv = ["python3", "-c", "import pathlib,sys;p=pathlib.Path(sys.argv[1]);s=p.read_text();old=sys.argv[2];assert old and old in s;p.write_text(s.replace(old,sys.argv[3],int(sys.argv[4])))", value("path"), value("old_string"), value("new_string"), "-1" if values.get("replace_all", False) else "1"]
    elif name == "nmap_scan":
        scan = str(values.get("scan") or "version").strip().lower()
        if scan == "version":
            flags = ["-sV"]
        elif scan == "connect":
            flags = ["-sT"]
        elif scan == "scripts":
            flags = ["-sC", "-sV"]
        else:
            raise ValueError("nmap scan must be version, connect, or scripts")
        argv = ["nmap", *flags]
        port_expr = value("ports")
        if str(port_expr).strip().lower() == "all":
            argv += ["-p-"]
        else:
            argv += ["-p", port_expr]
        argv.append(value("target"))
    elif name == "port_scan":
        argv = ["nmap", "-sT"]
        port_expr = value("ports")
        if str(port_expr).strip().lower() == "all":
            argv += ["-p-"]
        else:
            argv += ["-p", port_expr]
        argv.append(value("target"))
    elif name == "sqlmap_scan":
        argv = ["sqlmap", "-u", value("url"), "--batch", f"--timeout={int(values.get('timeout', 30))}"]
    elif name == "nikto_scan":
        # Nikto checks its release API by default. Disable that unrelated
        # destination so the guard only sees the previewed target.
        argv = ["nikto", "-nocheck", "-h", value("target")]
    elif name == "whois_lookup":
        argv = ["whois", "-h", "whois.iana.org", "--no-recursion", value("domain")]
    elif name == "gobuster_dir":
        argv = ["gobuster", "dir", "-u", value("url"), "-w", "/usr/share/blackonyx/wordlists/common.txt"]
    elif name == "hydra_brute":
        if int(values.get("timeout", 60)) > 120:
            raise ValueError("Hydra runtime is limited to 120 seconds")
        argv = [
            "hydra", "-L", "/usr/share/blackonyx/wordlists/usernames.txt",
            "-P", "/usr/share/blackonyx/wordlists/passwords.txt", "-f", "-t", "2",
            value("target"), value("service"),
        ]
    elif name == "checksec":
        argv = ["checksec", f"--file={value('path')}"]
    elif name in {"decompile", "decompile_function"}:
        function = value("function")
        if name == "decompile" and not function:
            # Whole-binary pseudo-C: iterate every analyzed function.
            argv = ["r2", "-q", "-e", "scr.color=0", "-c", "aaa; pdc @@F", value("path")]
        else:
            if not re.fullmatch(r"(?:0x[0-9a-fA-F]+|[A-Za-z_][A-Za-z0-9_.]{0,127})", function):
                raise ValueError("Invalid function identifier")
            argv = ["r2", "-q", "-e", "scr.color=0", "-c", f"aaa; s {function}; pdc", value("path")]
    elif name == "disassemble":
        argv = ["objdump", "-d", value("path")]
    elif name == "disassemble_binary":
        argv = ["r2", "-q", "-c", "aaa; pd 100", value("path")]
    elif name == "extract_strings":
        argv = ["strings", "-n", str(int(values.get("min_length", 4))), value("path")]
    elif name == "run_binary":
        binary = PurePosixPath(value("path")).name.lower()
        if binary in {"nikto", "nmap", "sqlmap", "gobuster", "hydra", "whois", "tcpdump"}:
            raise ValueError("Use the dedicated Network Scanners tool instead of run_binary")
        if binary in _RUN_BINARY_SHELLS:
            raise ValueError("Use the Bash tool instead of run_binary")
        argv = ["timeout", str(int(values.get("timeout", 30))), value("path"), *shlex.split(value("args"))]
    elif name == "file_info":
        argv = ["file", value("path")]
    elif name == "search_gadgets":
        search = value("search")
        if not search or len(search) > 256 or "\n" in search:
            raise ValueError("A gadget search expression is required")
        argv = ["ropper", "--nocolor", "--file", value("path"), "--search", search]
    elif name == "cyclic_pattern":
        argv = ["python3", "-c", "from pwn import cyclic;import sys;print(cyclic(int(sys.argv[1])).decode())", value("size")]
    elif name in {"aes_encrypt", "aes_decrypt"}:
        code = (
            "import base64,os,sys;from cryptography.hazmat.primitives.ciphers.aead import AESGCM;"
            "key=bytes.fromhex(sys.argv[1]);data=sys.stdin.buffer.read();"
            + ("nonce=os.urandom(12);print(base64.b64encode(nonce+AESGCM(key).encrypt(nonce,data,None)).decode())"
               if name == "aes_encrypt" else
               "blob=base64.b64decode(data,validate=True);print(AESGCM(key).decrypt(blob[:12],blob[12:],None).decode())")
        )
        argv = ["python3", "-c", code, value("key")]
        stdin = value("data")
    elif name == "generate_yara_rule":
        rule_name = value("name")
        patterns = value("strings")
        condition = value("condition")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", rule_name):
            raise ValueError("YARA rule name must be a valid identifier")
        if not patterns or len(patterns) > 32_768 or "\x00" in patterns:
            raise ValueError("YARA strings must contain 1 to 32768 characters")
        if len(condition) > 2048 or "\x00" in condition:
            raise ValueError("YARA condition is empty or oversized")
        argv = [
            "python3", "-c",
            (
            "import json,re,sys,yara;"
            "name,raw,condition=sys.argv[1:4];"
            "items=[s for s in raw.splitlines() if s];"
            "assert 1<=len(items)<=128 and all(len(s)<=512 and s.isprintable() for s in items), 'invalid YARA strings';"
            "escape=lambda s:'\\\"'+s.replace('\\\\','\\\\\\\\').replace('\\\"','\\\\\\\"')+'\\\"';"
            "body='\\n'.join('        $s%d = %s'%(i,escape(s)) for i,s in enumerate(items));"
            "condition=condition.strip() or 'any of them';"
            "source='rule %s {\\n    strings:\\n%s\\n    condition:\\n        %s\\n}\\n'%(name,body,condition);"
            "yara.compile(source=source);print(source,end='')"
            ),
            rule_name, patterns, condition,
        ]
    elif name in {"decode_hex", "decode_base64", "encode_base64", "hash_data", "compute_threat_score", "extract_iocs"}:
        code = {
            "decode_hex": "import sys;print(bytes.fromhex(sys.stdin.read()).decode(errors='replace'))",
            "decode_base64": "import base64,sys;sys.stdout.buffer.write(base64.b64decode(sys.stdin.buffer.read(),validate=True))",
            "encode_base64": "import base64,sys;print(base64.b64encode(sys.stdin.buffer.read()).decode())",
            "hash_data": "import hashlib,sys;print(hashlib.new(sys.argv[1],sys.stdin.buffer.read()).hexdigest())",
            "compute_threat_score": "import json,sys;i=json.load(sys.stdin);s=min(sum(x.get('confidence',0) for x in i),100);print(json.dumps({'score':s,'verdict':'CRITICAL' if s>=75 else 'HIGH' if s>=50 else 'MEDIUM' if s>=25 else 'LOW'}))",
            "extract_iocs": "import re,sys;print('\\n'.join(re.findall(r'https?://[^\\s]+|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}|(?:[0-9]{1,3}\\.){3}[0-9]{1,3}',sys.stdin.read())))",
        }[name]
        argv = ["python3", "-c", code]
        if name == "hash_data":
            algorithm = value("algorithm").lower()
            if algorithm not in {"md5", "sha1", "sha256", "sha512"}:
                raise ValueError("Unsupported hash algorithm")
            argv.append(algorithm)
        stdin = value("iocs" if name == "compute_threat_score" else "text" if name == "extract_iocs" else "data")
    elif name == "analyze_pcap":
        argv = ["tshark", "-r", value("path")]
        display_filter = value("filter")
        if display_filter:
            argv += ["-Y", display_filter]
    elif name == "cast_keccak":
        argv = ["cast", "keccak", value("data")]
    elif name == "shodan_search":
        # Gateway-owned adapter; credentials never enter the toolbox runner.
        parse_query(value("query"))
        argv = ["__trusted_adapter__", "shodan_search"]
    elif name == "add_ioc_to_case":
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value("case_id")):
            raise ValueError("Invalid case id")
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", value("ioc_type")):
            raise ValueError("Invalid IOC type")
        ioc_value = value("ioc_value")
        if not ioc_value or len(ioc_value) > 4096 or "\x00" in ioc_value:
            raise ValueError("Invalid IOC value")
        # The app-owned endpoint executes this adapter after approval. This
        # marker must never be sent to the untrusted toolbox runner.
        argv = ["__trusted_adapter__", "add_ioc_to_case"]
    elif name == "tcpdump_capture":
        duration = int(values.get("duration", 10))
        capture_filter = value("filter")
        if not 1 <= duration <= 30 or len(capture_filter) > 256:
            raise ValueError("Capture is limited to 30 seconds and a 256-character filter")
        if capture_filter and not re.fullmatch(r"[A-Za-z0-9().:/_= -]{1,256}", capture_filter):
            raise ValueError("Capture filter contains unsupported syntax")
        argv = ["__trusted_adapter__", "tcpdump_capture"]
    elif name in {"check_solved", "submit_solution"}:
        challenge_id = value("challenge_id")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", challenge_id):
            raise ValueError("Challenge ID is invalid")
        if name == "submit_solution":
            solution = value("solution")
            if not solution or "\x00" in solution or len(solution.encode("utf-8")) > 16 * 1024:
                raise ValueError("Solution must be bounded text or JSON no larger than 16 KiB")
        argv = ["__trusted_adapter__", name]
    elif name == "cast_call":
        argv = ["cast", "call", value("to"), value("data"), "--rpc-url", value("rpc_url")]
    elif name == "cast_send":
        recipient, sender = value("to"), value("from")
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", recipient):
            raise ValueError("Transaction recipient must be a 20-byte hexadecimal address")
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", sender):
            raise ValueError("Unlocked Anvil sender must be a 20-byte hexadecimal address")
        data, amount = value("data"), value("value")
        if len(data) > 131074 or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", data):
            raise ValueError("Transaction calldata must be bounded even-length hexadecimal data")
        if not re.fullmatch(r"[0-9]{1,78}", amount) or int(amount) > (2**256 - 1):
            raise ValueError("Transaction value must be an unsigned wei amount")
        argv = [
            "python3", "/usr/share/blackonyx/anvil_send.py", value("rpc_url"),
            recipient, sender, data, amount,
        ]
    elif name == "compile_contracts":
        contract = value("path")
        if contract.endswith(".sol"):
            argv = ["/usr/local/bin/solc", "--bin", contract]
        else:
            argv = ["forge", "build", "--root", contract]
    elif name == "analyze_contract":
        argv = [
            "slither", value("path"), "--solc", "/usr/local/bin/solc",
            "--solc-disable-warnings", "--fail-none",
        ]
    elif name == "get_contract_storage":
        if not value("rpc_url"):
            raise ValueError("An approved RPC URL is required for storage reads")
        argv = ["cast", "storage", value("address"), value("slots"), "--rpc-url", value("rpc_url")]
    else:
        # Tools needing a provider, privileged capture, or a dedicated API
        # adapter must not silently run the legacy shell template.
        raise UnsupportedTool(f"{name} has no verified structured executor")
    # Validate the derived connection scope after tool-specific required fields
    # and formats. The same normalized values feed both the preview scope and
    # the argv, while callers receive the precise argument error first.
    if name in NETWORK_TOOLS:
        derive_network_scope(name, values)
    if any(not isinstance(part, str) or "\x00" in part or len(part) > 100000 for part in argv):
        raise ValueError("Invalid command argument")
    return {"argv": argv, "stdin": stdin}
