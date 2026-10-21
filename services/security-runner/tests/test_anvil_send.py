from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

HELPER_PATH = Path(__file__).resolve().parents[1] / "toolbox" / "anvil_send.py"
SPEC = importlib.util.spec_from_file_location("anvil_send", HELPER_PATH)
assert SPEC and SPEC.loader
anvil_send = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(anvil_send)

RPC = "http://10.88.0.2:8545"
TO = "0x0000000000000000000000000000000000000001"
FROM = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
HASH = "0x" + "a" * 64


def test_anvil_send_verifies_owned_node_and_uses_its_unlocked_account(monkeypatch):
    calls = []

    class FakeRpc:
        def __init__(self, endpoint):
            assert endpoint == "10.88.0.2:8545"

        def call(self, method, params=None):
            calls.append((method, params))
            return {
                "web3_clientVersion": "anvil/v1.3.1",
                "eth_chainId": "0x7a69",
                "eth_accounts": [FROM],
                "eth_sendTransaction": HASH,
                "eth_getTransactionReceipt": {"status": "0x1"},
            }[method]

    monkeypatch.setattr(anvil_send, "_Rpc", FakeRpc)
    argv = ["anvil_send.py", RPC, TO, FROM, "0x1234", "12"]
    assert anvil_send.send(argv) == HASH
    assert [method for method, _ in calls] == [
        "web3_clientVersion", "eth_chainId", "eth_accounts",
        "eth_sendTransaction", "eth_getTransactionReceipt",
    ]
    assert calls[3][1] == [{"from": FROM, "to": TO, "data": "0x1234", "value": "0xc"}]


@pytest.mark.parametrize("endpoint", [
    "https://10.88.0.2:8545", "http://127.0.0.1:8545",
    "http://8.8.8.8:8545", "http://10.88.0.2:8546",
    "http://10.88.0.2:8545/rpc", "http://user:pass@10.88.0.2:8545",
])
def test_anvil_send_rejects_endpoints_outside_registered_profile(endpoint):
    with pytest.raises(anvil_send.AnvilError):
        anvil_send._parse_inputs(["anvil_send.py", endpoint, TO, FROM, "0x", "0"])


def test_anvil_send_rejects_non_anvil_chain_or_locked_sender(monkeypatch):
    class FakeRpc:
        def __init__(self, _endpoint):
            pass

        def call(self, method, _params=None):
            return {
                "web3_clientVersion": "anvil/v1.3.1",
                "eth_chainId": "0x1",
                "eth_accounts": [],
            }[method]

    monkeypatch.setattr(anvil_send, "_Rpc", FakeRpc)
    argv = ["anvil_send.py", RPC, TO, FROM, "0x", "0"]
    with pytest.raises(anvil_send.AnvilError, match="chain ID"):
        anvil_send.send(argv)

    class NotAnvil(FakeRpc):
        def call(self, method, _params=None):
            if method == "web3_clientVersion":
                return "geth/v1"
            return super().call(method)

    monkeypatch.setattr(anvil_send, "_Rpc", NotAnvil)
    with pytest.raises(anvil_send.AnvilError, match="not an Anvil"):
        anvil_send.send(argv)

    class CorrectChainButLocked(FakeRpc):
        def call(self, method, _params=None):
            if method == "eth_chainId":
                return "0x7a69"
            return super().call(method)

    monkeypatch.setattr(anvil_send, "_Rpc", CorrectChainButLocked)
    with pytest.raises(anvil_send.AnvilError, match="unlocked Anvil"):
        anvil_send.send(argv)

    class FailedReceipt(FakeRpc):
        def call(self, method, _params=None):
            return {
                "web3_clientVersion": "anvil/v1.3.1",
                "eth_chainId": "0x7a69",
                "eth_accounts": [FROM],
                "eth_sendTransaction": HASH,
                "eth_getTransactionReceipt": {"status": "0x0"},
            }[method]

    monkeypatch.setattr(anvil_send, "_Rpc", FailedReceipt)
    with pytest.raises(anvil_send.AnvilError, match="did not succeed"):
        anvil_send.send(argv)
