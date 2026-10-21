from __future__ import annotations

import sys
from pathlib import Path

GATEWAY_ROOT = Path(__file__).resolve().parents[1] / "services" / "security-gateway"
if str(GATEWAY_ROOT) not in sys.path:
    sys.path.insert(0, str(GATEWAY_ROOT))

from security_gateway.llm_client import _control_tokens_from_openai_tool_calls
from security_gateway.parser import parse_tool_calls


def test_openai_tool_calls_become_control_tokens() -> None:
    text = _control_tokens_from_openai_tool_calls(
        [{
            "id": "call_1",
            "function": {
                "name": "file_info",
                "arguments": '{"path":"sample.bin"}',
            },
        }],
        "",
    )
    calls = parse_tool_calls(text)
    assert len(calls) == 1
    assert calls[0].name == "file_info"
    assert calls[0].arguments == {"path": "sample.bin"}


def test_json_tool_args_keep_urls_with_schemes() -> None:
    from security_gateway.parser import parse_tool_call

    parsed = parse_tool_call(
        'call:run_binary:c1{"path":"nikto","args":"http://sec.dw.style"}'
    )
    assert parsed is not None
    assert parsed.name == "run_binary"
    assert parsed.arguments == {"path": "nikto", "args": "http://sec.dw.style"}
