"""Send one approved transaction to an owned, unlocked Anvil test node.

The node performs signing through ``eth_sendTransaction``. No private key,
mnemonic, keystore, or RPC credential is accepted or passed to this process.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import re
import sys
import time
from urllib.parse import urlsplit

MAX_RPC_RESPONSE = 64 * 1024
MAX_CALLDATA_BYTES = 64 * 1024
CHAIN_ID = 31337


class AnvilError(RuntimeError):
    """The registered Anvil node did not meet the local transaction contract."""


def _parse_inputs(argv: list[str]) -> tuple[str, str, str, str, str]:
    if len(argv) != 6:
        raise AnvilError("invalid transaction input")
    endpoint, recipient, sender, data, amount = argv[1:]
    parsed = urlsplit(endpoint)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port or 8545
    except ValueError as exc:
        raise AnvilError("RPC endpoint must use a literal private IPv4 address") from exc
    if (
        parsed.scheme != "http" or address.version != 4 or not address.is_private
        or address.is_loopback or address.is_link_local or address.is_multicast
        or address.is_unspecified or address.is_reserved or port != 8545
        or parsed.username is not None or parsed.password is not None
        or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
    ):
        raise AnvilError("RPC endpoint is outside the registered Anvil policy")
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", recipient):
        raise AnvilError("recipient address is invalid")
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", sender):
        raise AnvilError("sender address is invalid")
    if not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", data) or len(data) > MAX_CALLDATA_BYTES * 2 + 2:
        raise AnvilError("calldata is invalid or oversized")
    if not re.fullmatch(r"[0-9]{1,78}", amount) or int(amount) > (2**256 - 1):
        raise AnvilError("transaction value is invalid")
    return f"{address}:{port}", recipient.lower(), sender.lower(), data.lower(), hex(int(amount))


class _Rpc:
    def __init__(self, endpoint: str):
        self.endpoint = endpoint
        self.request_id = 0

    def call(self, method: str, params: list[object] | None = None) -> object:
        self.request_id += 1
        body = json.dumps({
            "jsonrpc": "2.0", "id": self.request_id, "method": method,
            "params": params or [],
        }, separators=(",", ":")).encode("ascii")
        host, port_text = self.endpoint.rsplit(":", 1)
        connection = http.client.HTTPConnection(host, int(port_text), timeout=5)
        try:
            connection.request("POST", "/", body=body, headers={
                "Content-Type": "application/json", "Content-Length": str(len(body)),
                "Connection": "close",
            })
            response = connection.getresponse()
            if response.status != 200:
                raise AnvilError("Anvil RPC returned an unsuccessful status")
            raw = response.read(MAX_RPC_RESPONSE + 1)
            if len(raw) > MAX_RPC_RESPONSE:
                raise AnvilError("Anvil RPC response exceeded its limit")
        finally:
            connection.close()
        try:
            result = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AnvilError("Anvil RPC response was invalid") from exc
        if not isinstance(result, dict) or result.get("id") != self.request_id or "error" in result:
            raise AnvilError("Anvil RPC rejected the request")
        if "result" not in result:
            raise AnvilError("Anvil RPC omitted its result")
        return result["result"]


def send(argv: list[str]) -> str:
    endpoint, recipient, sender, data, amount = _parse_inputs(argv)
    rpc = _Rpc(endpoint)
    version = rpc.call("web3_clientVersion")
    if not isinstance(version, str) or "anvil/" not in version.casefold():
        raise AnvilError("RPC endpoint is not an Anvil node")
    chain_id = rpc.call("eth_chainId")
    if not isinstance(chain_id, str) or int(chain_id, 16) != CHAIN_ID:
        raise AnvilError("Anvil chain ID must be 31337")
    accounts = rpc.call("eth_accounts")
    if not isinstance(accounts, list) or sender not in {
        item.lower() for item in accounts if isinstance(item, str)
    }:
        raise AnvilError("sender is not an unlocked Anvil test account")
    tx_hash = rpc.call("eth_sendTransaction", [{
        "from": sender, "to": recipient, "data": data, "value": amount,
    }])
    if not isinstance(tx_hash, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash):
        raise AnvilError("Anvil returned an invalid transaction hash")
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        receipt = rpc.call("eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            if not isinstance(receipt, dict) or receipt.get("status") != "0x1":
                raise AnvilError("Anvil transaction did not succeed")
            return tx_hash
        time.sleep(0.25)
    raise AnvilError("Anvil did not confirm the transaction within 15 seconds")


if __name__ == "__main__":
    try:
        print(json.dumps({"status": "confirmed", "tx_hash": send(sys.argv)}))
    except (AnvilError, http.client.HTTPException, OSError, TimeoutError, ValueError) as exc:
        print(json.dumps({"status": "error", "reason": str(exc)[:200]}))
        raise SystemExit(1)
